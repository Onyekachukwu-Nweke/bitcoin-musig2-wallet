use musig2_nostr::{coordinator::Coordinator, signer::Signer, initialize_nostr};
use nostr::{Keys as NostrKeys, PublicKey as NostrPublicKey};
use clap::{Arg, Command};
use inquire::{Text, Confirm, Select};
use std::str::FromStr;
use std::sync::Arc;
use tokio;
use std::fs;
use clap::{Parser, Subcommand};
use musig2::KeyAggContext;
use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};
// use crate::cli::{coordinator, signer};
use crate::error::Result;

// pub mod cli;
// mod core;
mod error;
pub mod musig2_nostr;

// #[derive(Parser)]
// #[command(name = "musig2_nostr-nostr")]
// #[command(about = "Musig2 implementation with Nostr integration", long_about = None)]
// struct Cli {
//     #[command(subcommand)]
//     role: Role,
// }
//
// #[derive(Subcommand)]
// enum Role {
//     /// Run as a signer
//     Signer(signer::SignerCli),
//     /// Run as a coordinator
//     Coordinator(coordinator::CoordinatorCli),
// }
//
// #[tokio::main]
// async fn main() -> Result<()> {
//     let cli = Cli::parse();
//
//     match cli.role {
//         Role::Signer(signer_cli) => signer::run_signer_cli(signer_cli).await,
//         Role::Coordinator(coordinator_cli) => coordinator::run_coordinator_cli(coordinator_cli).await,
//     }
// }

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("core_bdk_wallet")
        .version("0.1.0")
        .about("BDK wallet with modular MuSig2 over Nostr, nonce validation, and key generation")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("signer")
                .about("Run as a signer")
                .arg(Arg::new("nostr_private_key").long("nostr-private-key").value_name("HEX").help("Nostr private key"))
                .arg(Arg::new("musig2_secret_key").long("musig2-secret-key").value_name("HEX").help("MuSig2 secret key"))
                .arg(Arg::new("coordinator_nostr_pubkey").long("coordinator-pubkey").value_name("HEX").help("Coordinator's Nostr public key"))
                .arg(Arg::new("session_id").long("session-id").value_name("ID").help("Session ID")),
        )
        .subcommand(
            Command::new("coordinator")
                .about("Run as a coordinator")
                .arg(Arg::new("nostr_private_key").long("nostr-private-key").value_name("HEX").help("Nostr private key"))
                .arg(Arg::new("expected_signers").long("expected-signers").value_name("NUMBER").help("Number of signers").required(true))
                .arg(Arg::new("session_id").long("session-id").value_name("ID").help("Session ID")),
        )
        .get_matches();

    let relay_urls = vec!["wss://relay.damus.io".to_string(), "wss://relay.nostr.band".to_string()];
    let secp = Secp256k1::new();

    match matches.subcommand() {
        Some(("signer", signer_matches)) => {
            let session_id = prompt_or_get("Enter session ID:", signer_matches.get_one::<String>("session_id"))?;
            let coordinator_nostr_pubkey = prompt_or_get("Enter Coordinator's Nostr public key (HEX):", signer_matches.get_one::<String>("coordinator_nostr_pubkey"))?;
            let coordinator_pk = NostrPublicKey::from_str(&coordinator_nostr_pubkey).unwrap();

            let mut signer = if fs::metadata("signer_keys.enc").is_ok() && Confirm::new("Load saved keys?").with_default(true).prompt().unwrap() {
                let password = Text::new("Enter password to decrypt keys:").prompt().unwrap();
                Signer::load_keys(&password, coordinator_pk, session_id.clone()).unwrap()
            } else if Confirm::new("Generate new keys?").with_default(true).prompt().unwrap() {
                let password = Text::new("Enter password to encrypt new keys:").prompt().unwrap();
                Signer::generate_and_store_keys(&password, coordinator_pk, session_id.clone()).unwrap()
            } else {
                let nostr_private_key = prompt_or_get("Enter your Nostr private key (HEX):", signer_matches.get_one::<String>("nostr_private_key"))?;
                let musig2_secret_key = prompt_or_get("Enter your MuSig2 secret key (HEX):", signer_matches.get_one::<String>("musig2_secret_key"))?;
                let secret_key = SecretKey::from_str(&musig2_secret_key).unwrap();
                let nostr_keys = NostrKeys::from_str(&nostr_private_key).unwrap();
                Signer::new(secret_key, nostr_keys, coordinator_pk, session_id.clone())
            };

            let mut client = signer.client.lock().await;
            initialize_nostr(&mut client, relay_urls.clone()).await.unwrap();
            drop(client);

            if !fs::metadata("signer_keys.enc").is_ok() && Confirm::new("Save keys?").with_default(false).prompt().unwrap() {
                let password = Text::new("Enter password to encrypt keys:").prompt().unwrap();
                signer.save_keys(&password).unwrap();
            }

            println!("Signer initialized with MuSig2 public key: {:?}", signer.public_key);
            println!("Nostr public key: {:?}", signer.nostr_keys.public_key());

            if Confirm::new("Register with coordinator?").with_default(true).prompt().unwrap() {
                signer.register_with_coordinator().await.unwrap();
            }
        }
        Some(("coordinator", coord_matches)) => {
            let session_id = prompt_or_get("Enter session ID:", coord_matches.get_one::<String>("session_id"))?;
            let nostr_private_key = prompt_or_get("Enter your Nostr private key (HEX):", coord_matches.get_one::<String>("nostr_private_key"))?;
            let expected_signers_str = coord_matches.get_one::<String>("expected_signers").expect("Expected signers is required");
            let expected_signers = expected_signers_str.parse::<usize>().unwrap();

            let nostr_keys = NostrKeys::from_str(&nostr_private_key).unwrap();
            let mut coordinator = Coordinator::new(nostr_keys, expected_signers, session_id.clone());

            let mut client = coordinator.client.lock().await;
            initialize_nostr(&mut client, relay_urls.clone()).await.unwrap();
            drop(client);

            println!("Coordinator initialized for session: {}", session_id);

            coordinator.collect_signer_registrations().await.unwrap();
            println!("All signers registered: {:?}", coordinator.signers);

            let musig2_pks: Vec<PublicKey> = coordinator.signers.values().cloned().collect();
            let key_agg_ctx = KeyAggContext::new(musig2_pks.clone()).unwrap();
            let aggregated_pubkey = key_agg_ctx.aggregated_pubkey();
            println!("Agg: {:?}", aggregated_pubkey);
        }
        _ => unreachable!("Exhausted list of subcommands"),
    }

    Ok(())
}

fn prompt_or_get(prompt: &str, arg: Option<&String>) -> Result<String> {
    Ok(if let Some(val) = arg {
        val.clone()
    } else {
        Text::new(prompt).prompt().unwrap()
    })
}