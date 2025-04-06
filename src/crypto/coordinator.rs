use musig2::{secp256k1::{Keypair, PublicKey, SecretKey, Message}, FirstRound, SecondRound, KeyAggContext, AggNonce};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use musig2::secp256k1::schnorr::Signature;

// Message we want all parties to sign
const MESSAGE_BYTES: &[u8] = b"This is a message that requires multiple signatures";


/// The Coordinator manages the multi-signature process
struct Coordinator {
    participants: Vec<Participant>,
    public_keys: Vec<PublicKey>,
    public_round1s: Vec<musig2::PublicRound1>,
    round2s: HashMap<usize, Round2>,
}

impl Coordinator {
    fn new(num_participants: usize) -> Self {
        let participants = (0..num_participants)
            .map(|id| Participant::new(id))
            .collect::<Vec<_>>();

        Self {
            participants,
            public_keys: Vec::new(),
            public_round1s: Vec::new(),
            round2s: HashMap::new(),
        }
    }

    // Initialize round 1 of the protocol
    fn initialize_round1(&mut self) {
        // Collect public keys from all participants
        self.public_keys = self.participants
            .iter()
            .map(|p| p.get_public_key())
            .collect();

        // Have each participant generate round1 data
        self.public_round1s = self.participants
            .iter_mut()
            .map(|p| p.generate_round1())
            .collect();

        println!("Round 1 initialized with {} participants", self.participants.len());
        println!("All public keys and round1 data collected");
    }

    // Create the key aggregation context
    fn create_key_agg_ctx(&self) -> KeyAggContext {
        KeyAggContext::new(&self.public_keys).expect("Failed to create key aggregation context")
    }

    // Create the aggregate nonce from all public round1 data
    fn create_agg_nonce(&self) -> AggNonce {
        AggNonce::new(&self.public_round1s).expect("Failed to create aggregate nonce")
    }

    // Execute round 2 to collect partial signatures
    fn execute_round2(&mut self, key_agg_ctx: &KeyAggContext, message: &Message, agg_nonce: &AggNonce) {
        for (i, participant) in self.participants.iter().enumerate() {
            let round2 = participant.generate_round2(key_agg_ctx, message, agg_nonce);
            self.round2s.insert(i, round2);
        }
        println!("Round 2 completed: Collected all {} partial signatures", self.participants.len());
    }

    // Aggregate all partial signatures (round2 data) into a single signature
    fn aggregate_signatures(&self) -> Signature {
        let mut round2s = Vec::new();
        for i in 0..self.participants.len() {
            round2s.push(self.round2s.get(&i).unwrap());
        }

        Signature::from(&round2s).expect("Failed to aggregate signatures")
    }

    // Verify the aggregated signature
    fn verify_signature(&self, key_agg_ctx: &KeyAggContext, message: &Message, signature: &Signature) -> bool {
        let verifying_key = key_agg_ctx.verifying_key();
        verifying_key.verify(message, signature).is_ok()
    }
}