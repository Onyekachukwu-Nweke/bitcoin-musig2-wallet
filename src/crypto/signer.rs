use musig2::{secp256k1::{Keypair, PublicKey, SecretKey, Message}, FirstRound, SecondRound, KeyAggContext, AggNonce};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use musig2::secp256k1::schnorr::Signature;

// Utility function to generate a random keypair for each participant
fn generate_keypair() -> Keypair {
    let mut rng = thread_rng();
    let secp = musig2::secp256k1::Secp256k1::new();
    let secret_bytes = (0..32).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();
    let secret_key = SecretKey::from_byte_array(&secret_bytes.as_ref()).unwrap();
    // let public_key = PublicKey::from(&secret_key);
    Keypair::from_secret_key(&secp, &secret_key)
}

/// Represents a participant in the multi-sig protocol
struct Participant {
    id: usize,
    keypair: Keypair,
    round1: Option<FirstRound>,
}

impl Participant {
    fn new(id: usize) -> Self {
        Self {
            id,
            keypair: generate_keypair(),
            round1: None,
        }
    }

    // Round 1: Generate round1 data (nonce commitment)
    fn generate_round1(&mut self) -> musig2::PublicRound1 {
        let mut rng = thread_rng();
        let round1 = Round1::new(&mut rng);
        let public_round1 = round1.public_round1();
        self.round1 = Some(round1);
        public_round1
    }

    // Round 2: Generate partial signature using round 1 data
    fn generate_round2(
        &self,
        key_agg_ctx: &KeyAggContext,
        message: &Message,
        agg_nonce: &AggNonce
    ) -> Round2 {
        let round1 = self.round1.as_ref().expect("Round1 should be generated before signing");

        Round2::new(
            round1,
            &self.keypair.secret_key,
            key_agg_ctx,
            message,
            agg_nonce
        ).expect("Failed to create Round2")
    }

    fn get_public_key(&self) -> PublicKey {
        self.keypair.public_key.clone()
    }
}