use musig2::{FirstRound, KeyAggContext, NonceSeed, PartialSignature, PubNonce, SecNonceSpices};
use musig2::secp256k1::Message;
use rand::rngs::OsRng;
use crate::musig2::keys::Keys;

pub struct Signer {
    pub id: String,
    pub keys: Keys,
    pub first_round: Option<FirstRound>,
}

impl Signer {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            keys: Keys::new(),
            first_round: None,
        }
    }

    // Round 1: Generate and share public nonce
    pub fn generate_nonce(&mut self, key_agg_ctx: &KeyAggContext, signer_index: usize) -> PubNonce {
        let nonce_seed = NonceSeed::from(&mut OsRng::default());
        let spices = SecNonceSpices::new();
        let first_round = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            signer_index,
            spices,
        ).expect("First round initialization failed");
        let pub_nonce = first_round.our_public_nonce();
        self.first_round = Some(first_round);
        pub_nonce
    }

    // Round 2: Sign the message using the collected nonces
    pub fn sign_message(&mut self, message: &[u8], pub_nonces: Vec<PubNonce>) -> PartialSignature {
        let first_round = self.first_round.take().expect("First round not initialized");
        let mut second_round = first_round;
        for (i, pub_nonce) in pub_nonces.iter().enumerate() {
            if i != signer_index {
                second_round.receive_nonce(i, pub_nonce.clone()).expect("Nonce reception failed");
            }
        }
        let second_round = second_round.finalize((), ()).expect("First round finalization failed");
        let msg = Message::from(message);
        second_round.sign(&self.keys.secret_key, &msg).expect("Partial signing failed")
    }
}
