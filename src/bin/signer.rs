use clap::{Parser, Subcommand};
use secp256k1::PublicKey;
use crate::error::Result;

#[derive(Parser)]
pub struct SignerCli {
    #[command(subcommand)]
    command: SignerCommand,
}

#[derive(Subcommand)]
pub enum SignerCommand {
    /// Generate a new keypair
    GenerateKey,

    /// Start a new signing session
    StartSession {
        session_id: String,
        pubkeys: Vec<String>,
        message: String,
    },

    /// Join an existing session
    JoinSession {
        session_id: String,
    },

    /// Submit a partial signature
    SubmitPartialSignature {
        session_id: String,
    },
}

pub async fn run_signer_cli() -> Result<()> {
    let cli = SignerCli::parse();

    match cli.command {
        SignerCommand::GenerateKey => {
            let keypair = MusigKeyPair::new()?;
            println!("Secret key: {}", hex::encode(keypair.secret_key().as_ref()));
            println!("Public key: {}", keypair.public_key());
        }
        SignerCommand::StartSession { session_id, pubkeys, message } => {
            // TODO: Implement session start
            println!("Starting session {} with message {}", session_id, message);
        }
        SignerCommand::JoinSession { session_id } => {
            // TODO: Implement session join
            println!("Joining session {}", session_id);
        }
        SignerCommand::SubmitPartialSignature { session_id } => {
            // TODO: Implement partial signature submission
            println!("Submitting partial signature for session {}", session_id);
        }
    }

    Ok(())
}