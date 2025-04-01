use config::{Config, File, FileFormat};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub data_dir: String,
    pub network: bitcoin::Network,
    pub nostr_relays: Vec<String>,
    pub bitcoin_node_url: String,
}

pub fn load_config() -> Result<Settings, config::ConfigError> {
    let mut config = Config::builder();

    // Add configuration files (e.g., config.toml)
    config = config.add_source(File::new("config.toml", FileFormat::Toml));

    // Add environment variables
    config = config.add_source(config::Environment::with_prefix("APP"));

    config.try_into()
}