use serde::{Serialize, Deserialize};
use nostr::Keys as NostrKeys;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Payload}};
use aes_gcm::aead::generic_array::GenericArray;
use std::fs;
use std::str::FromStr;
use hex;
use secp256k1::{SecretKey, Secp256k1};
use rand::{Rng, thread_rng};
use sha256;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyStore {
    musig2_secret_key: String,  // Hex-encoded MuSig2 secret key
    nostr_private_key: String,  // Hex-encoded Nostr private key
}

impl KeyStore {
    /// Create a new KeyStore from existing keys
    pub fn new(musig2_secret_key: SecretKey, nostr_keys: &NostrKeys) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(KeyStore {
            musig2_secret_key: hex::encode(musig2_secret_key.secret_bytes()),
            nostr_private_key: hex::encode(nostr_keys.secret_key().to_secret_bytes()),
        })
    }

    /// Generate new MuSig2 and Nostr keys, store them, and return them
    pub fn generate_and_store(password: &str) -> Result<(SecretKey, NostrKeys), Box<dyn std::error::Error>> {
        // Generate MuSig2 secret key
        let musig2_secret_key = SecretKey::new(&mut thread_rng());

        // Generate Nostr keys
        let nostr_keys = NostrKeys::generate();

        // Create KeyStore instance
        let key_store = KeyStore {
            musig2_secret_key: hex::encode(musig2_secret_key.secret_bytes()),
            nostr_private_key: hex::encode(nostr_keys.secret_key().to_secret_bytes()),
        };

        // Encrypt and save to file
        let json = serde_json::to_string(&key_store)?;
        let encrypted = encrypt_data(&json, password)?;
        fs::write("signer_keys.enc", encrypted)?;
        println!("Generated and saved keys to signer_keys.enc");

        Ok((musig2_secret_key, nostr_keys))
    }

    /// Save existing keys to file
    pub fn save(&self, password: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(self)?;
        let encrypted = encrypt_data(&json, password)?;
        fs::write("signer_keys.enc", encrypted)?;
        println!("Keys saved to signer_keys.enc");
        Ok(())
    }

    /// Load keys from file
    pub fn load(password: &str) -> Result<(SecretKey, NostrKeys), Box<dyn std::error::Error>> {
        let encrypted = fs::read("signer_keys.enc")?;
        let decrypted = decrypt_data(&encrypted, password)?;
        let key_store: KeyStore = serde_json::from_str(&decrypted)?;
        let musig2_secret_key = SecretKey::from_str(&key_store.musig2_secret_key)?;
        let nostr_keys = NostrKeys::new((&key_store.nostr_private_key).parse().unwrap());
        Ok((musig2_secret_key, nostr_keys))
    }
}

fn encrypt_data(data: &str, password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(&sha256::digest(password.as_bytes())[..32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = thread_rng().gen::<[u8; 12]>();
    let payload = Payload { msg: data.as_bytes(), aad: b"" };
    let encrypted = cipher.encrypt(&nonce.into(), payload).unwrap();
    Ok([nonce.to_vec(), encrypted].concat())
}

fn decrypt_data(encrypted: &[u8], password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = GenericArray::from_slice(&sha256::digest(password.as_bytes())[..32]);
    let cipher = Aes256Gcm::new(key);
    let (nonce, ciphertext) = encrypted.split_at(12);
    let payload = Payload { msg: ciphertext, aad: b"" };
    let decrypted = cipher.decrypt(nonce.into(), payload)?;
    Ok(String::from_utf8(decrypted)?)
}