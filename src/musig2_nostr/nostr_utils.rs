use std::time::Duration;
use nostr_sdk::Client;

pub async fn initialize_nostr(client: &mut Client, relay_urls: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    for url in relay_urls {
        client.add_relay(url).await?;
    }
    client.connect().await;
    Ok(())
}