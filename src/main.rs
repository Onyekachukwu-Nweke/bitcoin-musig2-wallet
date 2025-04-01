mod bin;
// mod core;
mod error;
mod musig2;

use clap::{Parser, Subcommand};
use crate::error::Result;

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
    Signer,
    /// Run as a coordinator
    Coordinator,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.role {
        Role::Signer => bin::signer::run_signer_cli().await,
        Role::Coordinator => bin::coordinator::run_coordinator_cli().await,
    }
}