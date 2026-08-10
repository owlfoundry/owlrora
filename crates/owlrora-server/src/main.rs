#![forbid(unsafe_code)]

use std::{env, error::Error, io, net::SocketAddr, process::ExitCode};

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Run,
    Help,
    Version,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("owlrora-server: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    match parse_command(env::args().skip(1)).map_err(invalid_input)? {
        Command::Run => serve().await?,
        Command::Help => print_help(),
        Command::Version => println!("owlrora-server {}", env!("CARGO_PKG_VERSION")),
    }
    Ok(())
}

fn parse_command(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let command = match arguments.next().as_deref() {
        None => Command::Run,
        Some("-h" | "--help") => Command::Help,
        Some("-V" | "--version") => Command::Version,
        Some(value) => return Err(format!("unexpected argument: {value}")),
    };
    if let Some(value) = arguments.next() {
        return Err(format!("unexpected argument: {value}"));
    }
    Ok(command)
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn print_help() {
    println!(
        "OwlRora Server — Routing and Observability for Reliable AI\n\n\
         Usage: owlrora-server [OPTIONS]\n\n\
         Options:\n  -h, --help       Print help\n  -V, --version    Print version"
    );
}

async fn serve() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .with_current_span(false)
        .with_span_list(false)
        .try_init()?;

    let address = env::var("OWLRORA_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse::<SocketAddr>()?;
    let listener = TcpListener::bind(address).await?;
    tracing::info!(%address, "server listening");

    owlrora_server::run(listener).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Command, String> {
        parse_command(arguments.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn starts_the_server_without_a_subcommand() {
        assert_eq!(parse(&[]), Ok(Command::Run));
    }

    #[test]
    fn supports_help_and_version_without_starting_the_server() {
        assert_eq!(parse(&["--help"]), Ok(Command::Help));
        assert_eq!(parse(&["--version"]), Ok(Command::Version));
    }

    #[test]
    fn rejects_subcommands_and_extra_arguments() {
        assert_eq!(
            parse(&["serve"]),
            Err("unexpected argument: serve".to_owned())
        );
        assert_eq!(
            parse(&["--help", "extra"]),
            Err("unexpected argument: extra".to_owned())
        );
    }
}
