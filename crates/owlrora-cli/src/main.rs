#![forbid(unsafe_code)]

mod client;
mod contract;
mod mcp;
mod output;
mod profile;
mod update;

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::Write as _,
    path::PathBuf,
    process::ExitCode,
};

use clap::{
    Arg, ArgAction, ArgMatches, Command, FromArgMatches as _, ValueHint,
    builder::{PossibleValuesParser, ValueParser},
};
#[cfg(test)]
use serde_json::json;

use crate::{
    client::{
        Invocation, ManagementClient, load_request_body, merge_secret_input, read_secret_stdin,
    },
    contract::{Operation, SecretInputMode, operation_by_cli_path, operations},
    mcp::McpOptions,
    profile::{
        KeySource, ManagementProfile, OutputFormat, ProfileOverrides, ProfileStore, TlsPolicy,
        valid_profile_name,
    },
};

#[derive(Default)]
struct CommandNode {
    operation: Option<&'static Operation>,
    children: BTreeMap<String, CommandNode>,
}

fn command() -> Command {
    let mut command = Command::new("owlrora")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Typed command-line and MCP client for OwlRora management")
        .arg_required_else_help(true)
        .arg(
            Arg::new("profile")
                .long("profile")
                .global(true)
                .value_name("NAME")
                .help("Select a stored management profile"),
        )
        .arg(
            Arg::new("server-url")
                .long("server-url")
                .global(true)
                .value_name("URL")
                .help("Override the selected profile's server URL"),
        )
        .arg(
            Arg::new("key-env")
                .long("key-env")
                .global(true)
                .value_name("VARIABLE")
                .conflicts_with_all(["key-file", "key-stdin"])
                .help("Read the Management API key from an environment variable"),
        )
        .arg(
            Arg::new("key-file")
                .long("key-file")
                .global(true)
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .conflicts_with_all(["key-env", "key-stdin"])
                .help("Read the Management API key from a permission-restricted file"),
        )
        .arg(
            Arg::new("key-stdin")
                .long("key-stdin")
                .global(true)
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["key-env", "key-file"])
                .help("Read the Management API key once from redirected standard input"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .global(true)
                .value_name("FORMAT")
                .value_parser(PossibleValuesParser::new(["table", "json"]))
                .help("Select human table or stable JSON output"),
        )
        .arg(
            Arg::new("insecure")
                .long("insecure")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Disable TLS certificate verification for development"),
        )
        .arg(
            Arg::new("allow-insecure-non-loopback")
                .long("allow-insecure-non-loopback")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Deliberately allow plaintext or verification-disabled non-loopback targets"),
        )
        .subcommand(profile_command())
        .subcommand(<update::UpdateArgs as clap::Args>::augment_args(
            Command::new("update").about("Update only this OwlRora CLI executable"),
        ))
        .subcommand(mcp_command());

    let mut root = CommandNode::default();
    for operation in operations() {
        let mut node = &mut root;
        for segment in operation
            .cli_path
            .as_deref()
            .expect("client operations have CLI paths")
            .split_whitespace()
        {
            node = node.children.entry(segment.to_owned()).or_default();
        }
        node.operation = Some(operation);
    }
    for (name, node) in root.children {
        command = command.subcommand(command_from_node(&name, node));
    }
    command
}

fn profile_command() -> Command {
    Command::new("profile")
        .about("Manage connection and credential-source profiles")
        .subcommand_required(true)
        .subcommand(Command::new("list").about("List stored profiles"))
        .subcommand(
            Command::new("show")
                .about("Show one stored profile without reading its credential")
                .arg(Arg::new("name").required(true)),
        )
        .subcommand(
            Command::new("set")
                .about("Create or replace a stored profile")
                .arg(Arg::new("name").required(true))
                .arg(
                    Arg::new("profile-server-url")
                        .long("profile-server-url")
                        .required(true)
                        .value_name("URL"),
                )
                .arg(
                    Arg::new("profile-key-env")
                        .long("profile-key-env")
                        .value_name("VARIABLE")
                        .conflicts_with("profile-key-file"),
                )
                .arg(
                    Arg::new("profile-key-file")
                        .long("profile-key-file")
                        .value_name("FILE")
                        .value_hint(ValueHint::FilePath),
                )
                .arg(
                    Arg::new("profile-output")
                        .long("profile-output")
                        .value_parser(PossibleValuesParser::new(["table", "json"])),
                )
                .arg(
                    Arg::new("profile-insecure")
                        .long("profile-insecure")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("profile-allow-insecure-non-loopback")
                        .long("profile-allow-insecure-non-loopback")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a stored profile")
                .arg(Arg::new("name").required(true)),
        )
        .subcommand(
            Command::new("use")
                .about("Select the default stored profile")
                .arg(Arg::new("name").required(true)),
        )
}

fn mcp_command() -> Command {
    Command::new("mcp")
        .about("Run the bounded OwlRora management MCP server over stdio")
        .arg(
            Arg::new("toolset")
                .long("toolset")
                .value_name("NAME")
                .action(ArgAction::Append)
                .value_parser(PossibleValuesParser::new([
                    "read",
                    "write",
                    "secrets",
                    "operations",
                    "authority",
                ]))
                .help("Expose a bounded typed toolset; defaults to read"),
        )
        .arg(
            Arg::new("allow-write")
                .long("allow-write")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allow-secret-inputs")
                .long("allow-secret-inputs")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("allow-sensitive-results")
                .long("allow-sensitive-results")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("full-access")
                .long("full-access")
                .action(ArgAction::SetTrue)
                .conflicts_with_all([
                    "toolset",
                    "allow-write",
                    "allow-secret-inputs",
                    "allow-sensitive-results",
                ]),
        )
}

fn command_from_node(name: &str, node: CommandNode) -> Command {
    let mut command = Command::new(name.to_owned());
    if let Some(operation) = node.operation {
        command = command
            .about(format!("{} {}", operation.method, operation.path))
            .long_about(operation_help(operation));
        for parameter in operation.path_parameters() {
            command = command.arg(
                Arg::new(parameter.clone())
                    .required(true)
                    .value_name(parameter.to_ascii_uppercase())
                    .help("Opaque resource identifier"),
            );
        }
        for parameter in operation.query_parameters() {
            let mut argument = Arg::new(parameter.name.clone())
                .long(parameter.name.replace('_', "-"))
                .value_name(parameter.name.to_ascii_uppercase())
                .required(parameter.required);
            if parameter.is_integer() {
                argument = argument.value_parser(ValueParser::new(clap::value_parser!(u64)));
            }
            command = command.arg(argument);
        }
        if operation.accepts_body() {
            let source_help = if operation.secret_input.is_some() {
                "Read the JSON candidate from FILE, or '-' for redirected standard input; a FILE containing the protected field must be owner-only"
            } else {
                "Read the JSON candidate from FILE, or '-' for standard input"
            };
            let mut source = Arg::new("from")
                .long("from")
                .value_name("FILE")
                .value_hint(ValueHint::FilePath)
                .help(source_help);
            if operation
                .secret_input
                .as_ref()
                .is_some_and(|input| input.mode == SecretInputMode::ReplaceBody)
            {
                source = source.required_unless_present("secret-stdin");
            } else {
                source = source.required(true);
            }
            command = command.arg(source);
        }
        if let Some(secret_input) = &operation.secret_input {
            let mut argument = Arg::new("secret-stdin")
                .long("secret-stdin")
                .action(ArgAction::SetTrue)
                .help(format!(
                    "Read protected field {} from redirected standard input",
                    secret_input.field
                ));
            if secret_input.mode == SecretInputMode::ReplaceBody {
                argument = argument.conflicts_with("from");
            }
            command = command.arg(argument);
        }
        if operation.etag_precondition {
            command = command.arg(Arg::new("etag").long("etag").value_name("ETAG").help(
                "ETag from the source GET; may instead be embedded beside candidate in --from",
            ));
        }
        if operation.idempotency == "supported" {
            command = command.arg(
                Arg::new("idempotency-key")
                    .long("idempotency-key")
                    .value_name("KEY")
                    .help("Stable key for a deliberate retry of this exact candidate"),
            );
        }
    }
    if node.operation.is_none() {
        command = command
            .subcommand_required(true)
            .arg_required_else_help(true);
    }
    for (child_name, child) in node.children {
        command = command.subcommand(command_from_node(&child_name, child));
    }
    command
}

fn operation_help(operation: &Operation) -> String {
    let mut details = format!(
        "Checked operation {}\nRequired scopes: {}",
        operation.id,
        operation.required_scopes.join(", ")
    );
    if !operation.authorization_variants.is_empty() {
        let variants = operation
            .authorization_variants
            .iter()
            .map(|variant| {
                variant.condition.as_ref().map_or_else(
                    || variant.required_capability.clone(),
                    |condition| format!("{} ({condition})", variant.required_capability),
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            details,
            "\nAuthorization capability (any variant): {variants}"
        );
    }
    if operation.etag_precondition {
        details.push_str("\nRequires the candidate-bound ETag; conflicts are never retried.");
    }
    if operation.one_time_secret_response {
        details.push_str("\nReturns a one-time secret and is issued at most once.");
    }
    details
}

fn run(matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    match matches.subcommand() {
        Some(("profile", submatches)) => run_profile(submatches)?,
        Some(("update", submatches)) => {
            let arguments = update::UpdateArgs::from_arg_matches(submatches)?;
            update::run(&arguments)?;
        }
        Some(("mcp", submatches)) => {
            let profile = profile::resolve(&profile_overrides(matches)?)?;
            let client = ManagementClient::new(profile)?;
            mcp::run(&client, &mcp_options(submatches))?;
        }
        Some(_) => run_management(matches)?,
        None => unreachable!("clap requires a command"),
    }
    Ok(())
}

fn run_profile(matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let mut store = ProfileStore::load()?;
    match matches.subcommand() {
        Some(("list", _)) => {
            for name in store.profiles.keys() {
                let marker = if store.default_profile.as_deref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name}");
            }
        }
        Some(("show", arguments)) => {
            let name = arguments.get_one::<String>("name").unwrap();
            let profile = store
                .profiles
                .get(name)
                .ok_or_else(|| profile::ProfileError::UnknownProfile(name.clone()))?;
            println!("{}", serde_json::to_string_pretty(profile)?);
        }
        Some(("set", arguments)) => {
            let name = arguments.get_one::<String>("name").unwrap();
            if !valid_profile_name(name) {
                return Err(profile::ProfileError::InvalidProfileName.into());
            }
            let source = if let Some(path) = arguments.get_one::<String>("profile-key-file") {
                KeySource::File {
                    path: PathBuf::from(path),
                }
            } else {
                KeySource::Environment {
                    variable: arguments
                        .get_one::<String>("profile-key-env")
                        .cloned()
                        .unwrap_or_else(|| profile::DEFAULT_KEY_ENVIRONMENT_VARIABLE.to_owned()),
                }
            };
            let default_output = arguments
                .get_one::<String>("profile-output")
                .map(|value| OutputFormat::parse(value))
                .transpose()?;
            store.profiles.insert(
                name.clone(),
                ManagementProfile {
                    server_url: arguments
                        .get_one::<String>("profile-server-url")
                        .unwrap()
                        .clone(),
                    management_api_key_source: source,
                    tls_policy: TlsPolicy {
                        insecure_skip_verification: arguments.get_flag("profile-insecure"),
                        allow_insecure_non_loopback: arguments
                            .get_flag("profile-allow-insecure-non-loopback"),
                    },
                    default_output,
                },
            );
            store.save()?;
        }
        Some(("remove", arguments)) => {
            let name = arguments.get_one::<String>("name").unwrap();
            if store.profiles.remove(name).is_none() {
                return Err(profile::ProfileError::UnknownProfile(name.clone()).into());
            }
            if store.default_profile.as_deref() == Some(name) {
                store.default_profile = None;
            }
            store.save()?;
        }
        Some(("use", arguments)) => {
            let name = arguments.get_one::<String>("name").unwrap();
            if !store.profiles.contains_key(name) {
                return Err(profile::ProfileError::UnknownProfile(name.clone()).into());
            }
            store.default_profile = Some(name.clone());
            store.save()?;
        }
        Some((_, _)) | None => unreachable!("clap validates profile commands"),
    }
    Ok(())
}

fn run_management(matches: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let (path, arguments) = selected_command(matches);
    let operation =
        operation_by_cli_path(&path).expect("clap command comes from generated contract");
    let overrides = profile_overrides(matches)?;
    let mut invocation = Invocation::default();
    for parameter in operation.path_parameters() {
        invocation.path_arguments.insert(
            parameter.clone(),
            arguments.get_one::<String>(&parameter).unwrap().clone(),
        );
    }
    for parameter in operation.query_parameters() {
        if parameter.is_integer() {
            if let Some(value) = arguments.get_one::<u64>(&parameter.name) {
                invocation
                    .query
                    .insert(parameter.name.clone(), value.to_string());
            }
        } else if let Some(value) = arguments.get_one::<String>(&parameter.name) {
            invocation
                .query
                .insert(parameter.name.clone(), value.clone());
        }
    }
    if operation.etag_precondition {
        invocation.etag = arguments.get_one::<String>("etag").cloned();
    }
    if operation.idempotency == "supported" {
        invocation.idempotency_key = arguments
            .get_one::<String>("idempotency-key")
            .cloned()
            .or_else(|| {
                operation
                    .client_generated_idempotency_key
                    .then(|| uuid::Uuid::now_v7().to_string())
            });
    }
    let secret_from_stdin = operation.secret_input.is_some() && arguments.get_flag("secret-stdin");
    if operation.accepts_body()
        && let Some(source) = arguments.get_one::<String>("from")
    {
        if (overrides.key_stdin || secret_from_stdin) && source == "-" {
            return Err(client::ClientError::ConflictingStdin.into());
        }
        let protected_source = operation.secret_input.is_some() && !secret_from_stdin;
        let (body, etag) = load_request_body(source, invocation.etag.take(), protected_source)?;
        invocation.body = Some(body);
        invocation.etag = etag;
    }
    if secret_from_stdin {
        let secret_input = operation
            .secret_input
            .as_ref()
            .expect("secret flag is defined only for secret input operations");
        let secret = read_secret_stdin(overrides.key_stdin, &secret_input.field)?;
        invocation.body = Some(match secret_input.mode {
            SecretInputMode::ReplaceBody => secret,
            SecretInputMode::MergeIntoCandidate => merge_secret_input(
                invocation.body.take().expect("merge mode requires --from"),
                secret,
            )?,
        });
    }
    let resolved = profile::resolve(&overrides)?;
    let format = resolved.output;
    let client = ManagementClient::new(resolved)?;
    let response = client.invoke(operation, &invocation, "cli")?;
    output::print_response(&response, format, operation.one_time_secret_response)?;
    Ok(())
}

fn selected_command(matches: &ArgMatches) -> (String, &ArgMatches) {
    let mut path = Vec::new();
    let mut current = matches;
    while let Some((name, child)) = current.subcommand() {
        path.push(name);
        current = child;
    }
    (path.join(" "), current)
}

fn profile_overrides(matches: &ArgMatches) -> Result<ProfileOverrides, profile::ProfileError> {
    Ok(ProfileOverrides {
        profile: matches.get_one::<String>("profile").cloned(),
        server_url: matches.get_one::<String>("server-url").cloned(),
        key_environment: matches.get_one::<String>("key-env").cloned(),
        key_file: matches.get_one::<String>("key-file").map(PathBuf::from),
        key_stdin: matches.get_flag("key-stdin"),
        insecure_skip_verification: matches.get_flag("insecure"),
        allow_insecure_non_loopback: matches.get_flag("allow-insecure-non-loopback"),
        output: matches
            .get_one::<String>("output")
            .map(|value| OutputFormat::parse(value))
            .transpose()?,
    })
}

fn mcp_options(matches: &ArgMatches) -> McpOptions {
    let full_access = matches.get_flag("full-access");
    let toolsets = matches.get_many::<String>("toolset").map_or_else(
        || BTreeSet::from(["read".to_owned()]),
        |values| values.cloned().collect::<BTreeSet<_>>(),
    );
    McpOptions {
        toolsets,
        allow_write: matches.get_flag("allow-write"),
        allow_secret_inputs: matches.get_flag("allow-secret-inputs"),
        allow_sensitive_results: matches.get_flag("allow-sensitive-results"),
        full_access,
    }
}

fn main() -> ExitCode {
    let matches = command().get_matches();
    match run(&matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("owlrora: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_command_accepts_the_supported_controls() {
        let matches = command()
            .try_get_matches_from([
                "owlrora",
                "update",
                "--version",
                "cli-v1.2.3",
                "--dry-run",
                "--force",
                "--install-dir",
                "/tmp/owlrora-bin",
            ])
            .unwrap();
        let (_, arguments) = matches.subcommand().unwrap();
        let arguments = update::UpdateArgs::from_arg_matches(arguments).unwrap();
        assert_eq!(arguments.version.as_deref(), Some("cli-v1.2.3"));
        assert!(arguments.dry_run);
        assert!(arguments.force);
    }

    #[test]
    fn generated_management_commands_are_typed_and_bounded() {
        let matches = command()
            .try_get_matches_from([
                "owlrora",
                "--server-url",
                "http://127.0.0.1:8080",
                "system",
                "users",
                "list",
                "--limit",
                "20",
            ])
            .unwrap();
        let (path, arguments) = selected_command(&matches);
        assert_eq!(path, "system users list");
        assert_eq!(arguments.get_one::<u64>("limit"), Some(&20));
        assert!(
            command()
                .try_get_matches_from(["owlrora", "system", "raw-request"])
                .is_err()
        );
    }

    #[test]
    fn usage_commands_require_and_parse_generated_query_flags() {
        assert!(
            command()
                .try_get_matches_from(["owlrora", "system", "usage", "get"])
                .is_err()
        );
        let matches = command()
            .try_get_matches_from([
                "owlrora",
                "system",
                "usage",
                "breakdown",
                "--start",
                "2026-01-01T00:00:00Z",
                "--end",
                "2026-01-02T00:00:00Z",
                "--fact-family",
                "attempts",
                "--dimension",
                "origin",
                "--limit",
                "20",
            ])
            .unwrap();
        let (path, arguments) = selected_command(&matches);
        assert_eq!(path, "system usage breakdown");
        assert_eq!(
            arguments.get_one::<String>("start").unwrap(),
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(arguments.get_one::<u64>("limit"), Some(&20));
    }

    #[test]
    fn raw_keys_are_not_command_line_arguments() {
        assert!(
            command()
                .try_get_matches_from(["owlrora", "--key", "secret", "me", "get"])
                .is_err()
        );
    }

    #[test]
    fn one_time_commands_accept_only_protected_body_sources() {
        let operation = operations()
            .iter()
            .find(|operation| operation.id == "system.management_keys.create")
            .unwrap();
        assert!(operation.one_time_secret_response);
        assert!(
            command()
                .try_get_matches_from([
                    "owlrora",
                    "system",
                    "management-api-keys",
                    "create",
                    "--from",
                    "candidate.json",
                ])
                .is_ok()
        );
    }

    #[test]
    fn generated_secret_input_modes_are_descriptor_driven() {
        let merge = operation_by_cli_path("organization upstream-credentials create").unwrap();
        let merge_input = merge.secret_input.as_ref().unwrap();
        assert_eq!(merge_input.field, "secret");
        assert_eq!(merge_input.mode, SecretInputMode::MergeIntoCandidate);
        assert!(
            command()
                .try_get_matches_from([
                    "owlrora",
                    "organization",
                    "upstream-credentials",
                    "create",
                    "org-1",
                    "--from",
                    "candidate.json",
                    "--secret-stdin",
                ])
                .is_ok()
        );
        assert!(
            command()
                .try_get_matches_from([
                    "owlrora",
                    "organization",
                    "upstream-credentials",
                    "create",
                    "org-1",
                    "--secret-stdin",
                ])
                .is_err()
        );

        let replace =
            operation_by_cli_path("system egress-network-policies replace-custom-ca").unwrap();
        let replace_input = replace.secret_input.as_ref().unwrap();
        assert_eq!(replace_input.field, "custom_ca_pem");
        assert_eq!(replace_input.mode, SecretInputMode::ReplaceBody);
        assert!(
            command()
                .try_get_matches_from([
                    "owlrora",
                    "system",
                    "egress-network-policies",
                    "replace-custom-ca",
                    "policy-1",
                    "--secret-stdin",
                    "--etag",
                    "\"etag\"",
                ])
                .is_ok()
        );

        let codex = operation_by_cli_path("system upstream-credentials codex-login start").unwrap();
        assert!(codex.secret_input.is_none());
    }

    #[test]
    fn profile_display_never_resolves_or_prints_key_material() {
        let profile = ManagementProfile {
            server_url: "https://example.test".to_owned(),
            management_api_key_source: KeySource::Environment {
                variable: "TEST_KEY".to_owned(),
            },
            tls_policy: TlsPolicy::default(),
            default_output: Some(OutputFormat::Json),
        };
        let rendered = serde_json::to_string(&profile).unwrap();
        assert!(rendered.contains("TEST_KEY"));
        assert!(!rendered.contains("Bearer"));
        assert_eq!(
            json!(profile)["management_api_key_source"]["kind"],
            "environment"
        );
    }
}
