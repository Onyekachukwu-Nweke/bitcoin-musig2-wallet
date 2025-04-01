use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use rand::thread_rng;

pub struct Keys {
    pub keypair: Keypair,
}

impl Keys {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &sk);
        Self { keypair }
    }
}