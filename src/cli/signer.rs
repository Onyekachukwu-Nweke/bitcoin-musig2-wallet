use bdk::bitcoin::secp256k1::SecretKey;
use bdk::bitcoin::PublicKey;
use crate::musig2_nostr::{Signer, initialize_nostr};
use nostr::Keys as NostrKeys;
use clap::ArgMatches;
use inquire::{Confirm, Text};
use std::fs;
use std::str::FromStr;

use crate::cli::utils::prompt_or_get;

pub async fn run(matches: &ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = prompt_or_get("Enter session ID:", matches.get_one::<String>("session_id"))?;
    let coordinator_nostr_pubkey = prompt_or_get("Enter Coordinator's Nostr public key (HEX):", matches.get_one::<String>("coordinator_nostr_pubkey"))?;
    let coordinator_pk = PublicKey::from_str(&coordinator_nostr_pubkey)?;

    let relay_urls = vec!["wss://relay.damus.io".to_string(), "wss://relay.nostr.band".to_string()];

    let mut signer = if fs::metadata("signer_keys.enc").is_ok() && Confirm::new("Load saved keys?").with_default(true).prompt()? {
        let password = Text::new("Enter password to decrypt keys:").prompt()?;
        Signer::load_keys(&password, coordinator_pk, session_id.clone())?
    } else if Confirm::new("Generate new keys?").with_default(true).prompt()? {
        let password = Text::new("Enter password to encrypt new keys:").prompt()?;
        Signer::generate_and_store_keys(&password, coordinator_pk, session_id.clone())?
    } else {
        let nostr_private_key = prompt_or_get("Enter your Nostr private key (HEX):", matches.get_one::<String>("nostr_private_key"))?;
        let musig2_secret_key = prompt_or_get("Enter your MuSig2 secret key (HEX):", matches.get_one::<String>("musig2_secret_key"))?;
        let secret_key = SecretKey::from_str(&musig2_secret_key)?;
        let nostr_keys = NostrKeys::from_private_key_str(&nostr_private_key)?;
        Signer::new(secret_key, nostr_keys, coordinator_pk, session_id.clone())
    };

    let mut client = signer.client.lock().await;
    initialize_nostr(&mut client, relay_urls.clone()).await?;
    drop(client);

    if !fs::metadata("signer_keys.enc").is_ok() && Confirm::new("Save keys?").with_default(false).prompt()? {
        let password = Text::new("Enter password to encrypt keys:").prompt()?;
        signer.save_keys(&password)?;
    }

    println!("Signer initialized with MuSig2 public key: {:?}", signer.public_key);
    println!("Nostr public key: {:?}", signer.nostr_keys.public_key());

    if Confirm::new("Register with coordinator?").with_default(true).prompt()? {
        signer.register_with_coordinator().await?;

        if Confirm::new("Start the first round?").with_default(true).prompt()? {
            let pub_nonce = signer.start_first_round().await?;
            println!("Public nonce sent: {:?}", pub_nonce);

            let all_nonces = signer.wait_for_nonces_and_signal().await?;
            println!("Received all nonces: {:?}", all_nonces);

            if Confirm::new("Proceed to second round?").with_default(true).prompt()? {
                let partial_sig = signer.handle_second_round(all_nonces).await?;
                println!("Partial signature sent: {:?}", partial_sig);
            }
        }
    }

    Ok(())
}
