use clap::{Parser, Subcommand};
use crate::cli::{coordinator, signer};
use crate::error::Result;

pub mod cli;
// mod core;
mod error;
pub mod musig2;

#[derive(Parser)]
#[command(name = "musig2-nostr")]
#[command(about = "Musig2 implementation with Nostr integration", long_about = None)]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// Run as a signer
    Signer(signer::SignerCli),
    /// Run as a coordinator
    Coordinator(coordinator::CoordinatorCli),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.role {
        Role::Signer(signer_cli) => signer::run_signer_cli(signer_cli).await,
        Role::Coordinator(coordinator_cli) => coordinator::run_coordinator_cli(coordinator_cli).await,
    }
}