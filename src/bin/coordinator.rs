use clap::{Parser, Subcommand};
use error::Result;

#[derive(Parser)]
pub struct CoordinatorCli {
    #[command(subcommand)]
    command: CoordinatorCommand,
}

#[derive(Subcommand)]
pub enum CoordinatorCommand {
    /// Initialize a new Musig2 session
    InitSession {
        session_id: String,
        pubkeys: Vec<String>,
        message: String,
    },

    /// Collect partial signatures
    CollectSignatures {
        session_id: String,
    },

    /// Aggregate signatures
    AggregateSignatures {
        session_id: String,
    },
}

pub async fn run_coordinator_cli() -> Result<()> {
    let cli = CoordinatorCli::parse();

    match cli.command {
        CoordinatorCommand::InitSession { session_id, pubkeys, message } => {
            // TODO: Implement session initialization
            println!("Initializing session {} with message {}", session_id, message);
        }
        CoordinatorCommand::CollectSignatures { session_id } => {
            // TODO: Implement signature collection
            println!("Collecting signatures for session {}", session_id);
        }
        CoordinatorCommand::AggregateSignatures { session_id } => {
            // TODO: Implement signature aggregation
            println!("Aggregating signatures for session {}", session_id);
        }
    }

    Ok(())
}