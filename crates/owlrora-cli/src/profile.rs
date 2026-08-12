use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, IsTerminal as _, Read as _, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_KEY_ENVIRONMENT_VARIABLE: &str = "OWLRORA_MANAGEMENT_API_KEY";
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_PROFILE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Table,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Result<Self, ProfileError> {
        match value {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            _ => Err(ProfileError::InvalidOutput(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeySource {
    Environment { variable: String },
    File { path: PathBuf },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TlsPolicy {
    #[serde(default)]
    pub insecure_skip_verification: bool,
    #[serde(default)]
    pub allow_insecure_non_loopback: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagementProfile {
    pub server_url: String,
    pub management_api_key_source: KeySource,
    #[serde(default)]
    pub tls_policy: TlsPolicy,
    pub default_output: Option<OutputFormat>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProfileStore {
    pub default_profile: Option<String>,
    pub profiles: BTreeMap<String, ManagementProfile>,
}

#[derive(Clone, Debug)]
pub struct ProfileOverrides {
    pub profile: Option<String>,
    pub server_url: Option<String>,
    pub key_environment: Option<String>,
    pub key_file: Option<PathBuf>,
    pub key_stdin: bool,
    pub insecure_skip_verification: bool,
    pub allow_insecure_non_loopback: bool,
    pub output: Option<OutputFormat>,
}

pub struct ResolvedProfile {
    pub server_url: String,
    pub management_api_key: String,
    pub tls_policy: TlsPolicy,
    pub output: OutputFormat,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("cannot determine the OwlRora configuration directory")]
    MissingConfigDirectory,
    #[cfg(not(unix))]
    #[error(
        "secure profile and key files are unavailable on this platform; use explicit server flags with an environment or stdin key source"
    )]
    SecureFilesUnsupported,
    #[error("failed to read profiles from {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error(
        "profiles file {0} must be an owner-controlled, permission-restricted regular file and not a symlink"
    )]
    UnsafeProfilesFile(PathBuf),
    #[error("invalid profiles file {path}: {source}")]
    Invalid {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to write profiles to {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("management profile {0:?} does not exist")]
    UnknownProfile(String),
    #[error("profile name must contain only letters, digits, '.', '_', and '-'")]
    InvalidProfileName,
    #[error("no server URL is configured; select a profile or use --server-url")]
    MissingServerUrl,
    #[error("management key environment variable {0} is not set")]
    MissingKeyEnvironment(String),
    #[error(
        "management key file {0} must be an owner-controlled, permission-restricted regular file and not a symlink"
    )]
    UnsafeKeyFile(PathBuf),
    #[error("failed to read management key from {path}: {source}")]
    ReadKeyFile { path: PathBuf, source: io::Error },
    #[error("--key-stdin requires redirected standard input")]
    InteractiveKeyStdin,
    #[error("failed to read the management key from standard input: {0}")]
    ReadKeyStdin(io::Error),
    #[error("the management key is empty or exceeds {MAX_KEY_BYTES} bytes")]
    InvalidKey,
    #[error("unknown output format {0:?}; expected json or table")]
    InvalidOutput(String),
}

impl ProfileStore {
    pub fn load() -> Result<Self, ProfileError> {
        let path = profiles_path()?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ProfileError::Read { path, source }),
        };
        ensure_secure_file_support()?;
        if !restricted_regular_file(&metadata) {
            return Err(ProfileError::UnsafeProfilesFile(path));
        }
        let mut file = open_readonly_nofollow(&path).map_err(|source| ProfileError::Read {
            path: path.clone(),
            source,
        })?;
        let opened_metadata = file.metadata().map_err(|source| ProfileError::Read {
            path: path.clone(),
            source,
        })?;
        if !restricted_regular_file(&opened_metadata) {
            return Err(ProfileError::UnsafeProfilesFile(path));
        }
        let mut bytes = Vec::new();
        io::Read::by_ref(&mut file)
            .take((MAX_PROFILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|source| ProfileError::Read {
                path: path.clone(),
                source,
            })?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::UnsafeProfilesFile(path));
        }
        serde_json::from_slice(&bytes).map_err(|source| ProfileError::Invalid { path, source })
    }

    pub fn save(&self) -> Result<(), ProfileError> {
        ensure_secure_file_support()?;
        let path = profiles_path()?;
        let parent = path.parent().expect("profiles path has a parent");
        fs::create_dir_all(parent).map_err(|source| ProfileError::Write {
            path: parent.to_owned(),
            source,
        })?;
        restrict_directory(parent)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !restricted_regular_file(&metadata) => {
                return Err(ProfileError::UnsafeProfilesFile(path));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ProfileError::Write {
                    path: path.clone(),
                    source,
                });
            }
        }
        let bytes = serde_json::to_vec_pretty(self).expect("profile store is serializable");
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|source| ProfileError::Write {
                path: path.clone(),
                source,
            })?;
        restrict_file(temporary.path())?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.flush())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|source| ProfileError::Write {
                path: path.clone(),
                source,
            })?;
        temporary
            .persist(&path)
            .map_err(|error| ProfileError::Write {
                path: path.clone(),
                source: error.error,
            })?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ProfileError::Write {
                path: parent.to_owned(),
                source,
            })
    }
}

pub fn resolve(overrides: &ProfileOverrides) -> Result<ResolvedProfile, ProfileError> {
    let explicit_server_url = overrides
        .server_url
        .clone()
        .or_else(|| env::var("OWLRORA_SERVER_URL").ok());
    let default_key_available = env::var_os(DEFAULT_KEY_ENVIRONMENT_VARIABLE).is_some();
    let store = if should_load_profile_store(
        overrides,
        explicit_server_url.is_some(),
        default_key_available,
    ) {
        ProfileStore::load()?
    } else {
        ProfileStore::default()
    };
    let selected_name = overrides
        .profile
        .as_ref()
        .or(store.default_profile.as_ref());
    let selected = selected_name
        .map(|name| {
            store
                .profiles
                .get(name)
                .ok_or_else(|| ProfileError::UnknownProfile(name.clone()))
        })
        .transpose()?;

    let server_url = explicit_server_url
        .or_else(|| selected.map(|profile| profile.server_url.clone()))
        .ok_or(ProfileError::MissingServerUrl)?;
    let tls_policy = TlsPolicy {
        insecure_skip_verification: overrides.insecure_skip_verification
            || selected.is_some_and(|profile| profile.tls_policy.insecure_skip_verification),
        allow_insecure_non_loopback: overrides.allow_insecure_non_loopback
            || selected.is_some_and(|profile| profile.tls_policy.allow_insecure_non_loopback),
    };
    let management_api_key = if overrides.key_stdin {
        read_key_stdin()?
    } else if let Some(variable) = &overrides.key_environment {
        read_key_environment(variable)?
    } else if let Some(path) = &overrides.key_file {
        read_key_file(path)?
    } else if let Some(profile) = selected {
        read_key_source(&profile.management_api_key_source)?
    } else {
        read_key_environment(DEFAULT_KEY_ENVIRONMENT_VARIABLE)?
    };
    let output = overrides
        .output
        .or_else(|| selected.and_then(|profile| profile.default_output))
        .unwrap_or(OutputFormat::Table);

    Ok(ResolvedProfile {
        server_url,
        management_api_key,
        tls_policy,
        output,
    })
}

fn should_load_profile_store(
    overrides: &ProfileOverrides,
    explicit_server: bool,
    default_key_available: bool,
) -> bool {
    let fileless_key_available = overrides.key_stdin
        || overrides.key_environment.is_some()
        || (overrides.key_file.is_none() && default_key_available);
    overrides.profile.is_some() || !explicit_server || !fileless_key_available
}

pub fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub fn profiles_path() -> Result<PathBuf, ProfileError> {
    if let Some(directory) = env::var_os("OWLRORA_CONFIG_DIR") {
        return Ok(PathBuf::from(directory).join("profiles.json"));
    }
    if let Some(directory) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(directory)
            .join("owlrora")
            .join("profiles.json"));
    }
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/owlrora/profiles.json"))
        .ok_or(ProfileError::MissingConfigDirectory)
}

fn read_key_source(source: &KeySource) -> Result<String, ProfileError> {
    match source {
        KeySource::Environment { variable } => read_key_environment(variable),
        KeySource::File { path } => read_key_file(path),
    }
}

fn read_key_environment(variable: &str) -> Result<String, ProfileError> {
    let value =
        env::var(variable).map_err(|_| ProfileError::MissingKeyEnvironment(variable.to_owned()))?;
    validate_key(&value)
}

fn read_key_file(path: &Path) -> Result<String, ProfileError> {
    ensure_secure_file_support()?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ProfileError::ReadKeyFile {
        path: path.to_owned(),
        source,
    })?;
    if !restricted_regular_file(&metadata) {
        return Err(ProfileError::UnsafeKeyFile(path.to_owned()));
    }
    let mut file = open_readonly_nofollow(path).map_err(|source| ProfileError::ReadKeyFile {
        path: path.to_owned(),
        source,
    })?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| ProfileError::ReadKeyFile {
            path: path.to_owned(),
            source,
        })?;
    if !restricted_regular_file(&opened_metadata) {
        return Err(ProfileError::UnsafeKeyFile(path.to_owned()));
    }
    let mut bytes = Vec::new();
    io::Read::by_ref(&mut file)
        .take((MAX_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| ProfileError::ReadKeyFile {
            path: path.to_owned(),
            source,
        })?;
    let value = String::from_utf8(bytes).map_err(|error| ProfileError::ReadKeyFile {
        path: path.to_owned(),
        source: io::Error::new(io::ErrorKind::InvalidData, error),
    })?;
    validate_key(&value)
}

fn read_key_stdin() -> Result<String, ProfileError> {
    if io::stdin().is_terminal() {
        return Err(ProfileError::InteractiveKeyStdin);
    }
    let mut value = String::new();
    io::stdin()
        .take((MAX_KEY_BYTES + 1) as u64)
        .read_to_string(&mut value)
        .map_err(ProfileError::ReadKeyStdin)?;
    validate_key(&value)
}

fn validate_key(value: &str) -> Result<String, ProfileError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_KEY_BYTES {
        Err(ProfileError::InvalidKey)
    } else {
        Ok(value.to_owned())
    }
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)]
fn ensure_secure_file_support() -> Result<(), ProfileError> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_secure_file_support() -> Result<(), ProfileError> {
    Err(ProfileError::SecureFilesUnsupported)
}

#[cfg(unix)]
#[allow(clippy::verbose_bit_mask)]
fn restricted_regular_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    metadata.is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn restricted_regular_file(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn open_readonly_nofollow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
        .expect("O_NOFOLLOW fits platform custom flags");
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(nofollow)
        .open(path)
}

#[cfg(not(unix))]
fn open_readonly_nofollow(_path: &Path) -> io::Result<fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "reparse-point-safe credential file reads are unavailable",
    ))
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ProfileError::Write {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), ProfileError> {
    Err(ProfileError::SecureFilesUnsupported)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), ProfileError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ProfileError::Write {
            path: path.to_owned(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), ProfileError> {
    Err(ProfileError::SecureFilesUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_are_bounded_and_portable() {
        assert!(valid_profile_name("production.eu-1"));
        assert!(!valid_profile_name(""));
        assert!(!valid_profile_name("contains whitespace"));
        assert!(!valid_profile_name("../escape"));
    }

    #[test]
    fn output_formats_are_closed() {
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
        assert!(OutputFormat::parse("yaml").is_err());
    }

    #[test]
    fn complete_fileless_overrides_do_not_require_a_profile_store() {
        let overrides = ProfileOverrides {
            profile: None,
            server_url: Some("https://owlrora.example".to_owned()),
            key_environment: Some("TEST_MANAGEMENT_KEY".to_owned()),
            key_file: None,
            key_stdin: false,
            insecure_skip_verification: false,
            allow_insecure_non_loopback: false,
            output: None,
        };
        assert!(!should_load_profile_store(&overrides, true, false));
        assert!(should_load_profile_store(&overrides, false, false));

        let default_environment = ProfileOverrides {
            key_environment: None,
            ..overrides
        };
        assert!(!should_load_profile_store(&default_environment, true, true));
        assert!(should_load_profile_store(&default_environment, true, false));
    }

    #[cfg(not(unix))]
    #[test]
    fn credential_files_fail_closed_without_platform_security_validation() {
        assert!(matches!(
            ensure_secure_file_support(),
            Err(ProfileError::SecureFilesUnsupported)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_reject_symlinks_and_excess_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        fs::write(&key, "omk_test").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key_file(&key).unwrap(), "omk_test");

        let link = directory.path().join("link");
        symlink(&key, &link).unwrap();
        assert!(matches!(
            read_key_file(&link),
            Err(ProfileError::UnsafeKeyFile(_))
        ));

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_key_file(&key),
            Err(ProfileError::UnsafeKeyFile(_))
        ));
    }
}
