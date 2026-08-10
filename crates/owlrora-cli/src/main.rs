#![forbid(unsafe_code)]

mod update;

use std::{error::Error, process::ExitCode};

use clap::{CommandFactory as _, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "owlrora",
    version,
    about = "Command-line interface for OwlRora"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Update this CLI from an `OwlRora` GitHub Release.
    Update(update::UpdateArgs),
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Some(Command::Update(arguments)) => update::run(&arguments)?,
        None => {
            Cli::command().print_help()?;
            println!();
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
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
        let cli = Cli::try_parse_from([
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
        let Some(Command::Update(arguments)) = cli.command else {
            panic!("expected update command");
        };
        assert_eq!(arguments.version.as_deref(), Some("cli-v1.2.3"));
        assert!(arguments.dry_run);
        assert!(arguments.force);
        assert_eq!(
            arguments.install_dir.as_deref(),
            Some(std::path::Path::new("/tmp/owlrora-bin"))
        );
    }

    #[test]
    fn update_command_rejects_unknown_arguments() {
        assert!(Cli::try_parse_from(["owlrora", "update", "--unknown"]).is_err());
    }
}
