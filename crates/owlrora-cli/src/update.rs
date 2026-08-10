use std::{
    cmp::Ordering,
    env,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write as _},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Args;
use flate2::read::GzDecoder;
use fs2::FileExt as _;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const DEFAULT_REPOSITORY: &str = "owlfoundry/owlrora";
const RELEASE_TAG_PREFIX: &str = "cli-v";
const API_PAGE_SIZE: usize = 100;
const MAX_API_PAGES: usize = 10;
const MAX_RELEASE_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
const MAX_BINARY_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Install a specific CLI version instead of the latest stable release.
    #[arg(long, value_name = "SEMVER")]
    pub(crate) version: Option<String>,
    /// Print the selected update without downloading or installing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Reinstall or downgrade even when the selected version is not newer.
    #[arg(short, long)]
    pub(crate) force: bool,
    /// Override the directory containing the installed `owlrora` binary.
    #[arg(long, value_name = "DIRECTORY")]
    pub(crate) install_dir: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("invalid CLI release version {value}: {source}")]
    InvalidVersion {
        value: String,
        source: semver::Error,
    },
    #[error("failed to query CLI releases: {0}")]
    ReleaseQuery(String),
    #[error("no stable CLI release was found")]
    NoRelease,
    #[error("unsupported update target: {0}")]
    UnsupportedTarget(String),
    #[error("failed to download {resource}: {message}")]
    Download { resource: String, message: String },
    #[error("{resource} exceeds the {limit}-byte size limit")]
    ResponseTooLarge { resource: String, limit: usize },
    #[error("invalid SHA256SUMS: {0}")]
    InvalidChecksums(String),
    #[error("checksum mismatch for {0}")]
    ChecksumMismatch(String),
    #[error("invalid release archive: {0}")]
    InvalidArchive(String),
    #[error("cannot determine the current executable path: {0}")]
    CurrentExecutable(std::io::Error),
    #[error("CLI release versions must not contain build metadata: {0}")]
    BuildMetadata(String),
    #[error(
        "selected version {selected} is not newer than {current}; use --force to reinstall or downgrade"
    )]
    NotNewer { current: Version, selected: Version },
    #[error("another OwlRora CLI update is already using {0}")]
    InstallLocked(PathBuf),
    #[error("failed to install the update: {0}")]
    Install(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SelectedRelease {
    version: Version,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Debug)]
struct ReleaseAsset {
    archive_name: String,
    binary_name: &'static str,
}

#[derive(Debug)]
struct InstallTarget {
    directory: PathBuf,
    destination: PathBuf,
    is_running_executable: bool,
}

struct InstallLock {
    _file: fs::File,
}

pub fn run(arguments: &UpdateArgs) -> Result<(), UpdateError> {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is SemVer");
    supported_target()?;
    let explicit = arguments
        .version
        .as_deref()
        .map(explicit_release)
        .transpose()?;
    let binary_name = platform_binary_name();
    let target = install_target(arguments.install_dir.as_deref(), binary_name)?;
    let lock = if arguments.dry_run {
        None
    } else {
        Some(acquire_install_lock(&target.directory)?)
    };
    let selected = match explicit {
        Some(release) => release,
        None => latest_stable_release(&github_client()?, DEFAULT_REPOSITORY)?,
    };
    let asset = release_asset(&selected.version)?;

    if !update_is_required(&current, &selected.version, arguments.force)? {
        println!("owlrora {current} is already installed");
        return Ok(());
    }

    println!("owlrora {current} -> {}", selected.version);
    println!("release: {}", selected.tag);
    println!("archive: {}", asset.archive_name);
    println!("install directory: {}", target.directory.display());
    if arguments.dry_run {
        println!("status: dry-run");
        return Ok(());
    }

    let client = github_client()?;
    let binary = download_and_extract(&client, DEFAULT_REPOSITORY, &selected, &asset)?;
    install_binary_locked(
        &binary,
        &target.destination,
        target.is_running_executable,
        lock.as_ref()
            .expect("non-dry-run update holds the install lock"),
    )?;
    println!("updated owlrora to {}", selected.version);
    Ok(())
}

fn update_is_required(
    current: &Version,
    selected: &Version,
    force: bool,
) -> Result<bool, UpdateError> {
    if force {
        return Ok(true);
    }
    match selected.cmp(current) {
        Ordering::Equal => Ok(false),
        Ordering::Less => Err(UpdateError::NotNewer {
            current: current.clone(),
            selected: selected.clone(),
        }),
        Ordering::Greater => Ok(true),
    }
}

fn github_client() -> Result<reqwest::blocking::Client, UpdateError> {
    reqwest::blocking::Client::builder()
        .user_agent("owlrora-cli")
        .https_only(true)
        .redirect(github_redirect_policy())
        .connect_timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| UpdateError::ReleaseQuery(error.to_string()))
}

fn github_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many GitHub redirects");
        }
        if is_allowed_github_redirect_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

fn is_allowed_github_redirect_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.host_str().is_some_and(is_allowed_github_redirect_host)
}

fn is_allowed_github_redirect_host(host: &str) -> bool {
    matches!(host, "github.com" | "api.github.com") || host.ends_with(".githubusercontent.com")
}

fn explicit_release(value: &str) -> Result<SelectedRelease, UpdateError> {
    let version = parse_release_version(value)?;
    Ok(SelectedRelease {
        tag: format!("{RELEASE_TAG_PREFIX}{version}"),
        version,
    })
}

fn parse_release_version(value: &str) -> Result<Version, UpdateError> {
    let normalized = value
        .strip_prefix(RELEASE_TAG_PREFIX)
        .or_else(|| value.strip_prefix('v'))
        .unwrap_or(value);
    let version = Version::parse(normalized).map_err(|source| UpdateError::InvalidVersion {
        value: value.to_owned(),
        source,
    })?;
    if !version.build.is_empty() {
        return Err(UpdateError::BuildMetadata(value.to_owned()));
    }
    Ok(version)
}

fn latest_stable_release(
    client: &reqwest::blocking::Client,
    repository: &str,
) -> Result<SelectedRelease, UpdateError> {
    latest_stable_release_with(|page| {
        let url = format!(
            "https://api.github.com/repos/{repository}/releases?per_page={API_PAGE_SIZE}&page={page}"
        );
        let bytes = fetch_bytes(
            client,
            &url,
            "GitHub Releases API",
            MAX_RELEASE_PAGE_BYTES,
            Duration::from_secs(30),
            true,
        )?;
        serde_json::from_slice(&bytes).map_err(|error| UpdateError::ReleaseQuery(error.to_string()))
    })
}

fn latest_stable_release_with(
    mut fetch_page: impl FnMut(usize) -> Result<Vec<GitHubRelease>, UpdateError>,
) -> Result<SelectedRelease, UpdateError> {
    let mut releases = Vec::new();
    for page in 1..=MAX_API_PAGES {
        let page_releases = fetch_page(page)?;
        let complete = page_releases.len() < API_PAGE_SIZE;
        releases.extend(page_releases);
        if complete {
            return select_latest_stable(&releases).ok_or(UpdateError::NoRelease);
        }
    }
    Err(UpdateError::ReleaseQuery(format!(
        "GitHub Releases API exceeded the {MAX_API_PAGES}-page safety limit"
    )))
}

fn select_latest_stable(releases: &[GitHubRelease]) -> Option<SelectedRelease> {
    releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let value = release.tag_name.strip_prefix(RELEASE_TAG_PREFIX)?;
            let version = Version::parse(value).ok()?;
            if !version.pre.is_empty() || !version.build.is_empty() || version.to_string() != value
            {
                return None;
            }
            Some(SelectedRelease {
                version,
                tag: release.tag_name.clone(),
            })
        })
        .max_by(|left, right| {
            left.version
                .cmp(&right.version)
                .then_with(|| left.tag.cmp(&right.tag))
        })
}

fn release_asset(version: &Version) -> Result<ReleaseAsset, UpdateError> {
    let target = supported_target()?;
    let extension = if cfg!(windows) { "zip" } else { "tar.gz" };
    Ok(ReleaseAsset {
        archive_name: format!("owlrora-cli-{version}-{target}.{extension}"),
        binary_name: platform_binary_name(),
    })
}

fn platform_binary_name() -> &'static str {
    if cfg!(windows) {
        "owlrora.exe"
    } else {
        "owlrora"
    }
}

fn supported_target() -> Result<&'static str, UpdateError> {
    if cfg!(all(
        target_os = "linux",
        target_env = "gnu",
        target_arch = "x86_64"
    )) {
        return Ok("x86_64-unknown-linux-gnu");
    }
    if cfg!(all(
        target_os = "linux",
        target_env = "gnu",
        target_arch = "aarch64"
    )) {
        return Ok("aarch64-unknown-linux-gnu");
    }
    if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        return Ok("x86_64-apple-darwin");
    }
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        return Ok("aarch64-apple-darwin");
    }
    if cfg!(all(
        target_os = "windows",
        target_env = "msvc",
        target_arch = "x86_64"
    )) {
        return Ok("x86_64-pc-windows-msvc");
    }
    Err(UpdateError::UnsupportedTarget(format!(
        "{}-{}",
        env::consts::ARCH,
        env::consts::OS
    )))
}

fn download_and_extract(
    client: &reqwest::blocking::Client,
    repository: &str,
    release: &SelectedRelease,
    asset: &ReleaseAsset,
) -> Result<Vec<u8>, UpdateError> {
    let base_url = format!(
        "https://github.com/{repository}/releases/download/{}",
        release.tag
    );
    let checksums = fetch_bytes(
        client,
        &format!("{base_url}/SHA256SUMS"),
        "SHA256SUMS",
        MAX_CHECKSUM_BYTES,
        Duration::from_secs(30),
        false,
    )?;
    let expected = expected_checksum(&checksums, &asset.archive_name)?;
    let archive = fetch_bytes(
        client,
        &format!("{base_url}/{}", asset.archive_name),
        &asset.archive_name,
        MAX_ARCHIVE_BYTES,
        Duration::from_mins(15),
        false,
    )?;
    verify_archive_checksum(&archive, &expected, &asset.archive_name)?;
    extract_binary(&asset.archive_name, &archive, asset.binary_name)
}

fn verify_archive_checksum(
    archive: &[u8],
    expected: &str,
    archive_name: &str,
) -> Result<(), UpdateError> {
    let actual = format!("{:x}", Sha256::digest(archive));
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(UpdateError::ChecksumMismatch(archive_name.to_owned()))
    }
}

fn fetch_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    resource: &str,
    limit: usize,
    timeout: Duration,
    release_query: bool,
) -> Result<Vec<u8>, UpdateError> {
    let response = client
        .get(url)
        .timeout(timeout)
        .send()
        .map_err(|error| network_error(resource, &error, release_query))?;
    let status = response.status();
    if !status.is_success() {
        let message = format!("HTTP {status}");
        return if release_query {
            Err(UpdateError::ReleaseQuery(message))
        } else {
            Err(UpdateError::Download {
                resource: resource.to_owned(),
                message,
            })
        };
    }
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
    {
        return Err(UpdateError::ResponseTooLarge {
            resource: resource.to_owned(),
            limit,
        });
    }
    read_limited(response, resource, limit).map_err(|error| {
        if release_query {
            UpdateError::ReleaseQuery(error)
        } else {
            UpdateError::Download {
                resource: resource.to_owned(),
                message: error,
            }
        }
    })
}

fn network_error(resource: &str, error: &reqwest::Error, release_query: bool) -> UpdateError {
    if release_query {
        UpdateError::ReleaseQuery(error.to_string())
    } else {
        UpdateError::Download {
            resource: resource.to_owned(),
            message: error.to_string(),
        }
    }
}

fn read_limited(reader: impl Read, resource: &str, limit: usize) -> Result<Vec<u8>, String> {
    let limit_u64 = u64::try_from(limit).map_err(|error| error.to_string())?;
    let mut limited = reader.take(limit_u64.saturating_add(1));
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!("{resource} exceeds the {limit}-byte size limit"));
    }
    Ok(bytes)
}

fn expected_checksum(payload: &[u8], archive_name: &str) -> Result<String, UpdateError> {
    let text = std::str::from_utf8(payload)
        .map_err(|error| UpdateError::InvalidChecksums(error.to_string()))?;
    let mut expected = None;
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2
            || fields[0].len() != 64
            || !fields[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(UpdateError::InvalidChecksums(format!(
                "invalid entry on line {}",
                index + 1
            )));
        }
        let name = fields[1].strip_prefix('*').unwrap_or(fields[1]);
        if name.is_empty() || name.contains(['/', '\\']) {
            return Err(UpdateError::InvalidChecksums(format!(
                "invalid asset name on line {}",
                index + 1
            )));
        }
        if name == archive_name {
            if expected.is_some() {
                return Err(UpdateError::InvalidChecksums(format!(
                    "duplicate entry for {archive_name}"
                )));
            }
            expected = Some(fields[0].to_ascii_lowercase());
        }
    }
    expected.ok_or_else(|| UpdateError::InvalidChecksums(format!("no entry for {archive_name}")))
}

fn extract_binary(
    archive_name: &str,
    archive_bytes: &[u8],
    binary_name: &str,
) -> Result<Vec<u8>, UpdateError> {
    if archive_name.ends_with(".tar.gz") {
        return extract_tar_binary(archive_name, archive_bytes, binary_name);
    }
    if Path::new(archive_name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
    {
        return extract_zip_binary(archive_name, archive_bytes, binary_name);
    }
    Err(UpdateError::InvalidArchive(format!(
        "unsupported format for {archive_name}"
    )))
}

fn extract_tar_binary(
    archive_name: &str,
    archive_bytes: &[u8],
    binary_name: &str,
) -> Result<Vec<u8>, UpdateError> {
    let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(archive_bytes)));
    let entries = archive
        .entries()
        .map_err(|error| UpdateError::InvalidArchive(format!("{archive_name}: {error}")))?;
    let mut binary = None;
    for entry in entries {
        let mut entry = entry
            .map_err(|error| UpdateError::InvalidArchive(format!("{archive_name}: {error}")))?;
        let path = entry
            .path()
            .map_err(|error| UpdateError::InvalidArchive(error.to_string()))?;
        if path.as_ref() != Path::new(binary_name)
            || !entry.header().entry_type().is_file()
            || binary.is_some()
        {
            return Err(UpdateError::InvalidArchive(format!(
                "{archive_name} must contain exactly one top-level regular file named {binary_name}"
            )));
        }
        if entry.header().size().unwrap_or(u64::MAX)
            > u64::try_from(MAX_BINARY_BYTES).unwrap_or(u64::MAX)
        {
            return Err(UpdateError::InvalidArchive(format!(
                "{binary_name} exceeds the {MAX_BINARY_BYTES}-byte size limit"
            )));
        }
        binary = Some(
            read_limited(&mut entry, binary_name, MAX_BINARY_BYTES)
                .map_err(UpdateError::InvalidArchive)?,
        );
    }
    binary.ok_or_else(|| {
        UpdateError::InvalidArchive(format!("{archive_name} does not contain {binary_name}"))
    })
}

fn zip_entry_count(archive_name: &str, archive_bytes: &[u8]) -> Result<u16, UpdateError> {
    const END_RECORD_LENGTH: usize = 22;
    const MAX_COMMENT_LENGTH: usize = u16::MAX as usize;
    const SIGNATURE: &[u8; 4] = b"PK\x05\x06";

    if archive_bytes.len() < END_RECORD_LENGTH {
        return Err(UpdateError::InvalidArchive(format!(
            "{archive_name} has no ZIP end record"
        )));
    }
    let search_start = archive_bytes
        .len()
        .saturating_sub(END_RECORD_LENGTH + MAX_COMMENT_LENGTH);
    let search_end = archive_bytes.len() - END_RECORD_LENGTH;
    for offset in (search_start..=search_end).rev() {
        if &archive_bytes[offset..offset + SIGNATURE.len()] != SIGNATURE {
            continue;
        }
        let read_u16 = |relative: usize| {
            u16::from_le_bytes([
                archive_bytes[offset + relative],
                archive_bytes[offset + relative + 1],
            ])
        };
        let comment_length = usize::from(read_u16(20));
        if offset + END_RECORD_LENGTH + comment_length != archive_bytes.len() {
            continue;
        }
        let disk = read_u16(4);
        let central_directory_disk = read_u16(6);
        let entries_on_disk = read_u16(8);
        let entries = read_u16(10);
        if disk != 0
            || central_directory_disk != 0
            || entries_on_disk != entries
            || entries == u16::MAX
        {
            return Err(UpdateError::InvalidArchive(format!(
                "{archive_name} must be a single-disk non-ZIP64 archive"
            )));
        }
        if entries == 1 {
            let read_u32 = |relative: usize| {
                u32::from_le_bytes([
                    archive_bytes[offset + relative],
                    archive_bytes[offset + relative + 1],
                    archive_bytes[offset + relative + 2],
                    archive_bytes[offset + relative + 3],
                ])
            };
            let central_size = usize::try_from(read_u32(12)).unwrap_or(usize::MAX);
            let central_offset = usize::try_from(read_u32(16)).unwrap_or(usize::MAX);
            let central_end = central_offset.checked_add(central_size);
            if central_size < 46
                || central_end != Some(offset)
                || archive_bytes.get(central_offset..central_offset + 4) != Some(b"PK\x01\x02")
            {
                return Err(UpdateError::InvalidArchive(format!(
                    "{archive_name} has an inconsistent ZIP central directory"
                )));
            }
            let central_u16 = |relative: usize| {
                u16::from_le_bytes([
                    archive_bytes[central_offset + relative],
                    archive_bytes[central_offset + relative + 1],
                ])
            };
            let record_length = 46usize
                .checked_add(usize::from(central_u16(28)))
                .and_then(|length| length.checked_add(usize::from(central_u16(30))))
                .and_then(|length| length.checked_add(usize::from(central_u16(32))));
            if record_length != Some(central_size) {
                return Err(UpdateError::InvalidArchive(format!(
                    "{archive_name} must contain exactly one ZIP central-directory record"
                )));
            }
        }
        return Ok(entries);
    }
    Err(UpdateError::InvalidArchive(format!(
        "{archive_name} has no valid ZIP end record"
    )))
}

fn extract_zip_binary(
    archive_name: &str,
    archive_bytes: &[u8],
    binary_name: &str,
) -> Result<Vec<u8>, UpdateError> {
    if zip_entry_count(archive_name, archive_bytes)? != 1 {
        return Err(UpdateError::InvalidArchive(format!(
            "{archive_name} must contain exactly one top-level regular file named {binary_name}"
        )));
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|error| UpdateError::InvalidArchive(format!("{archive_name}: {error}")))?;
    if archive.len() != 1 {
        return Err(UpdateError::InvalidArchive(format!(
            "{archive_name} must contain exactly one top-level regular file named {binary_name}"
        )));
    }
    let mut entry = archive
        .by_index(0)
        .map_err(|error| UpdateError::InvalidArchive(error.to_string()))?;
    let enclosed = entry.enclosed_name().ok_or_else(|| {
        UpdateError::InvalidArchive(format!("{archive_name} contains an unsafe path"))
    })?;
    let unix_kind = entry.unix_mode().map_or(0, |mode| mode & 0o170_000);
    if enclosed != Path::new(binary_name) || !entry.is_file() || !matches!(unix_kind, 0 | 0o100_000)
    {
        return Err(UpdateError::InvalidArchive(format!(
            "{archive_name} must contain exactly one top-level regular file named {binary_name}"
        )));
    }
    if entry.size() > u64::try_from(MAX_BINARY_BYTES).unwrap_or(u64::MAX) {
        return Err(UpdateError::InvalidArchive(format!(
            "{binary_name} exceeds the {MAX_BINARY_BYTES}-byte size limit"
        )));
    }
    read_limited(&mut entry, binary_name, MAX_BINARY_BYTES).map_err(UpdateError::InvalidArchive)
}

fn install_target(
    install_directory: Option<&Path>,
    binary_name: &str,
) -> Result<InstallTarget, UpdateError> {
    if let Some(directory) = install_directory {
        let destination = directory.join(binary_name);
        return Ok(InstallTarget {
            is_running_executable: destination_is_current_executable(&destination),
            directory: directory.to_path_buf(),
            destination,
        });
    }

    let destination = env::current_exe().map_err(UpdateError::CurrentExecutable)?;
    let directory = destination.parent().map(Path::to_path_buf).ok_or_else(|| {
        UpdateError::CurrentExecutable(std::io::Error::other("the executable path has no parent"))
    })?;
    Ok(InstallTarget {
        directory,
        destination,
        is_running_executable: true,
    })
}

fn install_binary_locked(
    binary: &[u8],
    destination: &Path,
    is_running_executable: bool,
    _lock: &InstallLock,
) -> Result<(), UpdateError> {
    let install_dir = destination.parent().ok_or_else(|| {
        UpdateError::Install("the executable destination has no parent".to_owned())
    })?;
    let mut staged = tempfile::Builder::new()
        .prefix(".owlrora-update-")
        .tempfile_in(install_dir)
        .map_err(|error| UpdateError::Install(error.to_string()))?;
    staged
        .write_all(binary)
        .and_then(|()| staged.flush())
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| UpdateError::Install(error.to_string()))?;
    set_executable(staged.path())?;

    if is_running_executable {
        replace_current_executable(staged.path(), destination)?;
    } else {
        replace_other_destination(staged.path(), destination)?;
    }
    Ok(())
}

fn replace_current_executable(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    let backup = tempfile::Builder::new()
        .prefix(".owlrora-backup-")
        .tempfile_in(destination.parent().ok_or_else(|| {
            UpdateError::Install("the executable destination has no parent".to_owned())
        })?)
        .map_err(|error| UpdateError::Install(error.to_string()))?;
    fs::copy(destination, backup.path())
        .and_then(|_| backup.as_file().sync_all())
        .map_err(|error| UpdateError::Install(error.to_string()))?;

    if let Err(replacement_error) = self_replace::self_replace(source) {
        if !destination.exists()
            && let Err(rollback_error) =
                fs::copy(backup.path(), destination).and_then(|_| set_executable_io(destination))
        {
            return Err(UpdateError::Install(format!(
                "{replacement_error}; rollback failed for {}: {rollback_error}",
                destination.display()
            )));
        }
        return Err(UpdateError::Install(replacement_error.to_string()));
    }
    Ok(())
}

fn acquire_install_lock(install_dir: &Path) -> Result<InstallLock, UpdateError> {
    fs::create_dir_all(install_dir)
        .map_err(|error| UpdateError::Install(format!("{}: {error}", install_dir.display())))?;
    let path = install_dir.join(".owlrora-update.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| UpdateError::Install(format!("{}: {error}", path.display())))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(InstallLock { _file: file }),
        Err(error) if is_lock_contended(&error) => Err(UpdateError::InstallLocked(path)),
        Err(error) => Err(UpdateError::Install(format!("{}: {error}", path.display()))),
    }
}

fn is_lock_contended(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

fn destination_is_current_executable(destination: &Path) -> bool {
    let Ok(current) = env::current_exe().and_then(fs::canonicalize) else {
        return false;
    };
    destination
        .canonicalize()
        .is_ok_and(|candidate| candidate == current)
}

#[cfg(unix)]
fn replace_other_destination(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    fs::rename(source, destination)
        .map_err(|error| UpdateError::Install(format!("{}: {error}", destination.display())))
}

#[cfg(windows)]
fn replace_other_destination(source: &Path, destination: &Path) -> Result<(), UpdateError> {
    replace_other_destination_with(source, destination, |from, to| fs::rename(from, to))
}

#[cfg(windows)]
fn replace_other_destination_with(
    source: &Path,
    destination: &Path,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), UpdateError> {
    if !destination.exists() {
        return rename(source, destination)
            .map_err(|error| UpdateError::Install(format!("{}: {error}", destination.display())));
    }

    let parent = destination.parent().ok_or_else(|| {
        UpdateError::Install("the executable destination has no parent".to_owned())
    })?;
    let backup_directory = tempfile::Builder::new()
        .prefix(".owlrora-backup-")
        .tempdir_in(parent)
        .map_err(|error| UpdateError::Install(error.to_string()))?;
    let backup_name = destination.file_name().ok_or_else(|| {
        UpdateError::Install("the executable destination has no file name".to_owned())
    })?;
    let backup = backup_directory.path().join(backup_name);
    rename(destination, &backup)
        .map_err(|error| UpdateError::Install(format!("{}: {error}", destination.display())))?;

    if let Err(replacement_error) = rename(source, destination) {
        if let Err(rollback_error) = rename(&backup, destination) {
            let retained_backup = backup_directory.keep().join(backup_name);
            return Err(UpdateError::Install(format!(
                "{replacement_error}; rollback failed for {}: {rollback_error}; original binary retained at {}",
                destination.display(),
                retained_backup.display()
            )));
        }
        return Err(UpdateError::Install(format!(
            "{}: {replacement_error}",
            destination.display()
        )));
    }

    if let Err(error) = fs::remove_file(&backup) {
        eprintln!(
            "owlrora: warning: update succeeded but backup cleanup failed for {}: {error}",
            backup.display()
        );
    }
    Ok(())
}

fn set_executable(path: &Path) -> Result<(), UpdateError> {
    set_executable_io(path)
        .map_err(|error| UpdateError::Install(format!("{}: {error}", path.display())))
}

#[cfg(unix)]
fn set_executable_io(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_executable_io(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use flate2::{Compression, write::GzEncoder};
    use zip::{ZipWriter, write::SimpleFileOptions};

    use super::*;

    fn release(tag_name: &str, draft: bool, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag_name.to_owned(),
            draft,
            prerelease,
        }
    }

    fn tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(u64::try_from(content.len()).unwrap());
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, *content).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn tar_link(entry_type: tar::EntryType) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("target").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "owlrora", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn oversized_tar_header() -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_path("owlrora").unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(u64::try_from(MAX_BINARY_BYTES).unwrap() + 1);
        header.set_mode(0o755);
        header.set_cksum();
        let mut payload = header.as_bytes().to_vec();
        payload.extend_from_slice(&[0; 1024]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_with_raw_path(path: &[u8]) -> Vec<u8> {
        assert!(path.len() < 100);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(6);
        header.set_mode(0o755);
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_cksum();
        let mut payload = header.as_bytes().to_vec();
        payload.extend_from_slice(b"binary");
        payload.resize(1024, 0);
        payload.extend_from_slice(&[0; 1024]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&payload).unwrap();
        encoder.finish().unwrap()
    }

    fn tar_non_file(entry_type: tar::EntryType) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "owlrora", std::io::empty())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn zip_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, content) in entries {
            writer
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn zip_directory(name: &str) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .add_directory(name, SimpleFileOptions::default())
            .unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn zip_with_unix_mode(name: &str, mode: u32) -> Vec<u8> {
        let mut bytes = zip_archive(&[(name, b"target")]);
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        bytes[central + 5] = 3;
        bytes[central + 38..central + 42].copy_from_slice(&(mode << 16).to_le_bytes());
        bytes
    }

    fn zip_with_duplicate_names() -> Vec<u8> {
        let original = b"second_.exe";
        let replacement = b"owlrora.exe";
        assert_eq!(original.len(), replacement.len());
        let mut bytes = zip_archive(&[("owlrora.exe", b"first"), ("second_.exe", b"second")]);
        let mut offset = 0;
        while let Some(relative) = bytes[offset..]
            .windows(original.len())
            .position(|window| window == original)
        {
            let start = offset + relative;
            bytes[start..start + replacement.len()].copy_from_slice(replacement);
            offset = start + replacement.len();
        }
        bytes
    }

    fn zip_with_oversized_declaration() -> Vec<u8> {
        let mut bytes = zip_archive(&[("owlrora.exe", b"binary")]);
        let size = (u32::try_from(MAX_BINARY_BYTES).unwrap() + 1).to_le_bytes();
        let local = bytes
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        bytes[local + 22..local + 26].copy_from_slice(&size);
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .unwrap();
        bytes[central + 24..central + 28].copy_from_slice(&size);
        bytes
    }

    #[test]
    fn parses_plain_and_prefixed_versions() {
        assert_eq!(
            parse_release_version("0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert_eq!(
            parse_release_version("v0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert_eq!(
            parse_release_version("cli-v0.0.2").unwrap(),
            Version::new(0, 0, 2)
        );
        assert_eq!(
            parse_release_version("1.2.3-rc.1").unwrap(),
            Version::parse("1.2.3-rc.1").unwrap()
        );
        assert!(parse_release_version("latest").is_err());
        assert!(parse_release_version("../0.0.2").is_err());
        assert!(matches!(
            parse_release_version("1.2.3+build.1"),
            Err(UpdateError::BuildMetadata(_))
        ));
    }

    #[test]
    fn version_direction_requires_force_for_reinstall_or_downgrade() {
        let current = Version::new(2, 0, 0);
        assert!(!update_is_required(&current, &current, false).unwrap());
        assert!(matches!(
            update_is_required(&current, &Version::new(1, 0, 0), false),
            Err(UpdateError::NotNewer { .. })
        ));
        assert!(update_is_required(&current, &Version::new(3, 0, 0), false).unwrap());
        assert!(update_is_required(&current, &current, true).unwrap());
        assert!(update_is_required(&current, &Version::new(1, 0, 0), true).unwrap());
    }

    #[test]
    fn github_redirects_remain_on_github_https_origins() {
        assert!(is_allowed_github_redirect_url(
            &reqwest::Url::parse("https://github.com/release").unwrap()
        ));
        assert!(is_allowed_github_redirect_url(
            &reqwest::Url::parse("https://api.github.com/repos").unwrap()
        ));
        assert!(is_allowed_github_redirect_url(
            &reqwest::Url::parse("https://release-assets.githubusercontent.com/asset").unwrap()
        ));
        assert!(!is_allowed_github_redirect_url(
            &reqwest::Url::parse("http://github.com/release").unwrap()
        ));
        assert!(!is_allowed_github_redirect_url(
            &reqwest::Url::parse("https://github.com:4443/release").unwrap()
        ));
        assert!(!is_allowed_github_redirect_url(
            &reqwest::Url::parse("https://github.com.example.org/release").unwrap()
        ));
    }

    #[test]
    fn selects_the_highest_canonical_stable_cli_release() {
        let releases = vec![
            release("server-v9.0.0", false, false),
            release("cli-v0.0.2", false, false),
            release("cli-v0.0.4", true, false),
            release("cli-v0.0.3-rc.1", false, true),
            release("cli-v0.0.3", false, false),
            release("cli-v0.0.5+rebuilt", false, false),
            release("cli-v01.0.0", false, false),
        ];

        assert_eq!(
            select_latest_stable(&releases),
            Some(SelectedRelease {
                version: Version::new(0, 0, 3),
                tag: "cli-v0.0.3".to_owned(),
            })
        );
    }

    #[test]
    fn stable_selection_rejects_mislabeled_prereleases() {
        let releases = vec![release("cli-v1.0.0-rc.1", false, false)];
        assert_eq!(select_latest_stable(&releases), None);
    }

    #[test]
    fn release_discovery_rejects_unbounded_pagination() {
        let mut calls = 0;
        let result = latest_stable_release_with(|page| {
            calls += 1;
            Ok((0..API_PAGE_SIZE)
                .map(|index| release(&format!("server-v{page}.{index}.0"), false, false))
                .collect())
        });
        assert!(matches!(result, Err(UpdateError::ReleaseQuery(_))));
        assert_eq!(calls, MAX_API_PAGES);
    }

    #[test]
    fn checksum_inventory_requires_one_exact_valid_entry() {
        let name = "owlrora-cli-1.2.3-x86_64-unknown-linux-gnu.tar.gz";
        let hash = "a".repeat(64);
        let payload = format!("{hash}  unrelated.tar.gz\n{hash}  {name}\n");
        assert_eq!(expected_checksum(payload.as_bytes(), name).unwrap(), hash);

        let duplicate = format!("{hash}  {name}\n{hash} *{name}\n");
        assert!(expected_checksum(duplicate.as_bytes(), name).is_err());
        assert!(expected_checksum(b"not-a-checksum\n", name).is_err());

        let actual = Sha256::digest(b"archive");
        assert!(verify_archive_checksum(b"archive", &format!("{actual:x}"), name).is_ok());
        assert!(verify_archive_checksum(b"tampered", &format!("{actual:x}"), name).is_err());
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_body() {
        assert_eq!(
            read_limited(Cursor::new(b"1234"), "fixture", 4).unwrap(),
            b"1234"
        );
        assert!(read_limited(Cursor::new(b"12345"), "fixture", 4).is_err());
    }

    #[test]
    fn tar_archive_requires_one_exact_regular_binary() {
        let valid = tar_archive(&[("owlrora", b"binary")]);
        assert_eq!(
            extract_binary("asset.tar.gz", &valid, "owlrora").unwrap(),
            b"binary"
        );

        let extra = tar_archive(&[("owlrora", b"binary"), ("extra", b"unexpected")]);
        assert!(extract_binary("asset.tar.gz", &extra, "owlrora").is_err());
        let nested = tar_archive(&[("nested/owlrora", b"binary")]);
        assert!(extract_binary("asset.tar.gz", &nested, "owlrora").is_err());
        let duplicate = tar_archive(&[("owlrora", b"first"), ("owlrora", b"second")]);
        assert!(extract_binary("asset.tar.gz", &duplicate, "owlrora").is_err());
        assert!(
            extract_binary(
                "asset.tar.gz",
                &tar_link(tar::EntryType::Symlink),
                "owlrora"
            )
            .is_err()
        );
        assert!(
            extract_binary("asset.tar.gz", &tar_link(tar::EntryType::Link), "owlrora").is_err()
        );
        assert!(
            extract_binary(
                "asset.tar.gz",
                &tar_non_file(tar::EntryType::Fifo),
                "owlrora"
            )
            .is_err()
        );
        assert!(
            extract_binary("asset.tar.gz", &tar_with_raw_path(b"../owlrora"), "owlrora").is_err()
        );
        assert!(
            extract_binary("asset.tar.gz", &tar_with_raw_path(b"/owlrora"), "owlrora").is_err()
        );
        assert!(extract_binary("asset.tar.gz", &oversized_tar_header(), "owlrora").is_err());
    }

    #[test]
    fn zip_archive_requires_one_exact_regular_binary() {
        let valid = zip_archive(&[("owlrora.exe", b"binary")]);
        assert_eq!(
            extract_binary("asset.zip", &valid, "owlrora.exe").unwrap(),
            b"binary"
        );

        let extra = zip_archive(&[("owlrora.exe", b"binary"), ("extra.exe", b"unexpected")]);
        assert!(extract_binary("asset.zip", &extra, "owlrora.exe").is_err());
        let nested = zip_archive(&[("nested/owlrora.exe", b"binary")]);
        assert!(extract_binary("asset.zip", &nested, "owlrora.exe").is_err());
        let traversal = zip_archive(&[("../owlrora.exe", b"binary")]);
        assert!(extract_binary("asset.zip", &traversal, "owlrora.exe").is_err());
        let absolute = zip_archive(&[("/owlrora.exe", b"binary")]);
        assert!(extract_binary("asset.zip", &absolute, "owlrora.exe").is_err());
        assert!(extract_binary("asset.zip", &zip_with_duplicate_names(), "owlrora.exe").is_err());
        assert!(extract_binary("asset.zip", &zip_directory("owlrora.exe"), "owlrora.exe").is_err());
        assert!(
            extract_binary(
                "asset.zip",
                &zip_with_unix_mode("owlrora.exe", 0o120_777),
                "owlrora.exe"
            )
            .is_err()
        );
        assert!(
            extract_binary(
                "asset.zip",
                &zip_with_oversized_declaration(),
                "owlrora.exe"
            )
            .is_err()
        );
    }

    #[test]
    fn dry_run_does_not_create_an_explicit_install_directory() {
        let root = tempfile::tempdir().unwrap();
        let install_dir = root.path().join("not-created");
        run(&UpdateArgs {
            version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            dry_run: true,
            force: true,
            install_dir: Some(install_dir.clone()),
        })
        .unwrap();
        assert!(!install_dir.exists());
    }

    #[test]
    fn default_install_target_is_the_exact_running_path() {
        let target = install_target(None, platform_binary_name()).unwrap();
        assert_eq!(target.destination, env::current_exe().unwrap());
        assert!(target.is_running_executable);
    }

    #[test]
    fn concurrent_install_lock_is_rejected() {
        const CHILD_ENV: &str = "OWLRORA_LOCK_TEST_DIRECTORY";
        if let Some(directory) = env::var_os(CHILD_ENV) {
            assert!(matches!(
                acquire_install_lock(Path::new(&directory)),
                Err(UpdateError::InstallLocked(_))
            ));
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let _lock = acquire_install_lock(directory.path()).unwrap();
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "update::tests::concurrent_install_lock_is_rejected",
                "--nocapture",
            ])
            .env(CHILD_ENV, directory.path())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn non_running_destination_is_replaced_from_a_staged_file() {
        let directory = tempfile::tempdir().unwrap();
        let binary_name = if cfg!(windows) {
            "owlrora-test.exe"
        } else {
            "owlrora-test"
        };
        let destination = directory.path().join(binary_name);
        fs::write(&destination, b"old").unwrap();
        let lock = acquire_install_lock(directory.path()).unwrap();
        install_binary_locked(b"new", &destination, false, &lock).unwrap();
        assert_eq!(fs::read(destination).unwrap(), b"new");
    }

    #[test]
    fn running_executable_is_replaced_in_a_child_process() {
        const CHILD_ENV: &str = "OWLRORA_SELF_REPLACE_TEST_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let destination = env::current_exe().unwrap();
            let directory = destination.parent().unwrap();
            let lock = acquire_install_lock(directory).unwrap();
            install_binary_locked(b"replacement", &destination, true, &lock).unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let copied = directory.path().join(if cfg!(windows) {
            "owlrora-renamed.exe"
        } else {
            "owlrora-renamed"
        });
        fs::copy(env::current_exe().unwrap(), &copied).unwrap();
        let status = std::process::Command::new(&copied)
            .args([
                "--exact",
                "update::tests::running_executable_is_replaced_in_a_child_process",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read(copied).unwrap(), b"replacement");
    }

    #[cfg(windows)]
    #[test]
    fn windows_alternate_replacement_rolls_back_after_a_move_failure() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("staged.exe");
        let destination = directory.path().join("owlrora.exe");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();
        let mut calls = 0;
        let error = replace_other_destination_with(&source, &destination, |from, to| {
            calls += 1;
            if calls == 2 {
                Err(std::io::Error::other("injected replacement failure"))
            } else {
                fs::rename(from, to)
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected replacement failure"));
        assert_eq!(fs::read(destination).unwrap(), b"old");
        assert_eq!(fs::read(source).unwrap(), b"new");
    }

    #[cfg(windows)]
    #[test]
    fn windows_alternate_replacement_reports_and_retains_a_failed_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("staged.exe");
        let destination = directory.path().join("owlrora.exe");
        fs::write(&source, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();
        let mut calls = 0;
        let error = replace_other_destination_with(&source, &destination, |from, to| {
            calls += 1;
            match calls {
                1 => fs::rename(from, to),
                2 => Err(std::io::Error::other("injected replacement failure")),
                _ => Err(std::io::Error::other("injected rollback failure")),
            }
        })
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("injected replacement failure"));
        assert!(message.contains("injected rollback failure"));
        assert!(message.contains("original binary retained at"));
        assert!(!destination.exists());
        assert_eq!(fs::read(source).unwrap(), b"new");
    }
}
