use secp256k1_zkp::{self, PublicKey, SecretKey, Message, Secp256k1, schnorr::Signature};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use rand::rngs::OsRng;
use std::collections::HashMap;
use anyhow::{anyhow, Result};
use serde::Serialize;
// use serde::Serialize;

/// MuSig2 key aggregation coefficient
/// Calculated as the hash of L||X_i were L is the multiset of all public keys.
pub struct KeyAggCoef(pub [u8; 32]);

/// Public nonce for MuSig2 signing protocol
pub struct PublicNonce {
    pub r1: PublicKey,
    pub r2: PublicKey,
}

/// Secret nonce for MuSig2 signing protocol
pub struct SecretNonce {
    pub k1: SecretKey,
    pub k2: SecretKey,
}

/// Aggregate public key with metadata
pub struct AggregateKey {
    /// The aggregated public key
    pub agg_pk: PublicKey,
    /// Per-signer coefficients
    pub coefficients: HashMap<PublicKey, KeyAggCoef>,
}

/// MuSig2 signing session
pub struct MuSig2Session {
    /// The message being signed
    pub message: Message,
    /// The aggregated public key
    pub agg_pk: AggregateKey,
    /// Public nonces from all signers
    pub public_nonces: Vec<(PublicKey, PublicNonce)>,
    /// Aggregated commitment value R
    pub agg_r: Option<PublicKey>,
    /// Challenge value e
    pub challenge: Option<[u8; 32]>,
}

/// MuSig2 implementation
pub struct MuSig2 {
    /// Secp256k1 context
    secp: Secp256k1<secp256k1::All>,
}

impl MuSig2 {
    /// Create a new MuSig2 instance
    pub fn new() -> Self {
        MuSig2 {
            secp: Secp256k1::new(),
        }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> (SecretKey, PublicKey) {
        let mut rng = OsRng;
        self.secp.generate_keypair(&mut rng)
    }

    /// Compute the key aggregation coefficient for a public key
    fn compute_key_agg_coef(&self, pubkeys: &[PublicKey], target_pubkey: &PublicKey) -> KeyAggCoef {
        // Sort public keys
        let mut sorted_pubkeys = pubkeys.to_vec();
        sorted_pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

        // Create L as the concatenation of all public keys
        let mut l = Vec::new();
        for pk in &sorted_pubkeys {
            l.extend_from_slice(&pk.serialize());
        }

        // Compute KeyAggCoef = H(L||X_i)
        let mut hasher = sha256::Hash::engine();
        hasher.input(&l);
        hasher.input(&target_pubkey.serialize());

        let hash = sha256::Hash::from_engine(hasher);

        KeyAggCoef(*hash.as_ref())
    }

    /// Aggregate public keys using MuSig2 algorithm
    pub fn aggregate_keys(&self, pubkeys: &[PublicKey]) -> Result<AggregateKey> {
        if pubkeys.is_empty() {
            return Err(anyhow!("Cannot aggregate empty set of keys"));
        }

        let mut agg_pk: Option<PublicKey> = None;
        let mut coefficients = HashMap::new();

        for pubkey in pubkeys {
            // Compute key aggregation coefficient
            let coef = self.compute_key_agg_coef(pubkeys, pubkey);

            // Convert coefficient to scalar
            let coef_scalar = SecretKey::from_slice(&coef.0)?;

            // Multiply public key by coefficient: X_i * a_i
            let tweaked_pk = pubkey.mul_tweak(&self.secp, &coef_scalar.into())?;

            // Add to aggregate key: P = ∑(X_i * a_i)
            if let Some(current_agg_pk) = agg_pk {
                agg_pk = Some(current_agg_pk.combine(&tweaked_pk)?);
            } else {
                agg_pk = Some(tweaked_pk);
            }

            // Store coefficient
            coefficients.insert(*pubkey, coef);
        }

        Ok(AggregateKey {
            agg_pk: agg_pk.unwrap(),
            coefficients,
        })
    }

    /// Generate a new secret nonce for signing
    pub fn generate_nonce(&self) -> SecretNonce {
        let mut rng = OsRng;

        let k1 = SecretKey::new(&mut rng);
        let k2 = SecretKey::new(&mut rng);

        SecretNonce { k1, k2 }
    }

    /// Get the public nonce from a secret nonce
    pub fn get_public_nonce(&self, secret_nonce: &SecretNonce) -> PublicNonce {
        let r1 = PublicKey::from_secret_key(&self.secp, &secret_nonce.k1);
        let r2 = PublicKey::from_secret_key(&self.secp, &secret_nonce.k2);

        PublicNonce { r1, r2 }
    }

    /// Initialize a new signing session
    pub fn start_signing_session(
        &self,
        message: &[u8],
        agg_key: AggregateKey,
        public_nonces: Vec<(PublicKey, PublicNonce)>,
    ) -> MuSig2Session {
        // Hash the message to 32 bytes using SHA-256
        let message_hash = sha256::Hash::hash(message);
        let msg = Message::from_digest_slice(&message_hash[..]).expect("32 bytes");

        MuSig2Session {
            message: msg,
            agg_pk: agg_key,
            public_nonces,
            agg_r: None,
            challenge: None,
        }
    }

    /// Compute the aggregated R value and challenge
    pub fn compute_challenge(&self, session: &mut MuSig2Session) -> Result<()> {
        if session.agg_r.is_some() {
            return Ok(());  // Already computed
        }

        // Generate the aggregated R value
        // In MuSig2, this is R = ∑R_i where R_i = R_i1 + b*R_i2
        // and b = H(L||R_1^(1)||...||R_n^(1)||m)

        // First, compute the commitment hash b
        let mut hasher = sha256::Hash::engine();

        // Add all first nonce points R_i1
        for (_, nonce) in &session.public_nonces {
            hasher.input(&nonce.r1.serialize());
        }

        // Add the message
        hasher.input(&session.message[..]);

        let b_hash = sha256::Hash::from_engine(hasher);
        let b = SecretKey::from_slice(&b_hash.as_ref())?;

        // Now compute R = ∑(R_i1 + b*R_i2)
        let mut agg_r: Option<PublicKey> = None;

        for (_, nonce) in &session.public_nonces {
            // R_i = R_i1 + b*R_i2
            let r_i2_b = nonce.r2.mul_tweak(&self.secp, &b.into())?;
            let r_i = nonce.r1.combine(&r_i2_b)?;

            // Add to aggregate
            if let Some(current_agg_r) = agg_r {
                agg_r = Some(current_agg_r.combine(&r_i)?);
            } else {
                agg_r = Some(r_i);
            }
        }

        // Store the aggregated R
        session.agg_r = agg_r;

        // Compute the Schnorr challenge e = H(R||P||m)
        let mut challenge_hasher = sha256::Hash::engine();
        challenge_hasher.input(&session.agg_r.unwrap().serialize());
        challenge_hasher.input(&session.agg_pk.agg_pk.serialize());
        challenge_hasher.input(&session.message[..]);

        let challenge = sha256::Hash::from_engine(challenge_hasher);
        session.challenge = Some(challenge.to_byte_array());

        Ok(())
    }

    /// Create a partial signature for a participant
    pub fn sign(
        &self,
        session: &MuSig2Session,
        pubkey: &PublicKey,
        seckey: &SecretKey,
        nonce: &SecretNonce,
    ) -> Result<[u8; 32]> {
        // Ensure challenge is computed
        if session.agg_r.is_none() || session.challenge.is_none() {
            return Err(anyhow!("Challenge not computed"));
        }

        // Get key aggregation coefficient
        let coef = match session.agg_pk.coefficients.get(pubkey) {
            Some(c) => c,
            None => return Err(anyhow!("Public key not part of aggregation")),
        };

        // Compute b value as in compute_challenge
        let mut hasher = sha256::Hash::engine();
        for (_, n) in &session.public_nonces {
            hasher.input(&n.r1.serialize());
        }
        hasher.input(&session.message[..]);

        let b_hash = sha256::Hash::from_engine(hasher);
        let b = SecretKey::from_slice(&b_hash.as_ref())?;

        // Convert challenge to scalar
        let e = SecretKey::from_slice(&session.challenge.unwrap())?;

        // Convert coefficient to scalar
        let a_i = SecretKey::from_slice(&coef.0)?;

        // Compute partial signature s_i = k_i1 + b*k_i2 + e*a_i*x_i
        // First: k_i = k_i1 + b*k_i2
        let k_i2_b = nonce.k2.mul_tweak(&b.into())?;
        let k_i = nonce.k1.add_tweak(&k_i2_b.into())?;

        // Next: e*a_i*x_i
        let e_ai = e.mul_tweak(&a_i.into())?;
        let e_ai_xi = seckey.mul_tweak(&e_ai.into())?;

        // Finally: s_i = k_i + e*a_i*x_i
        let s_i = k_i.add_tweak(&e_ai_xi.into())?;

        // Extract the 32-byte array from the SecretKey
        let mut s_bytes: [u8; 32] = [0u8; 32];
        s_bytes.copy_from_slice(s_i.as_ref());
        println!("Partial signature for pubkey {:?}: {:?}", pubkey, s_bytes);
        Ok(s_bytes)
    }

    /// Aggregate partial signatures into a final signature
    pub fn aggregate_signatures(
        &self,
        session: &MuSig2Session,
        partial_sigs: &[[u8; 32]],
    ) -> Result<Signature> {
        println!("Agg beginning");
        if session.agg_r.is_none() || session.challenge.is_none() {
            return Err(anyhow!("Challenge not computed"));
        }

        println!("Agg beginning 2");

        if partial_sigs.is_empty() {
            return Err(anyhow!("No partial signatures to aggregate"));
        }

        println!("Agg beginning 3");

        // Initialize with the first partial signature
        let mut s_bytes = partial_sigs[0].clone(); // Start with the first partial signature
        println!("Are you here: Before partial sig loop, first sig: {:?}", s_bytes);

        // Accumulate the rest of the partial signatures
        for sig in &partial_sigs[1..] {
            let current_scalar = SecretKey::from_slice(&s_bytes)?;
            let next_scalar = SecretKey::from_slice(sig)?;
            let result = current_scalar.add_tweak(&next_scalar.into())?;
            s_bytes.copy_from_slice(result.as_ref());
        }

        // Ensure the final scalar is valid
        let s_scalar = SecretKey::from_slice(&s_bytes)?;

        // Construct full Schnorr signature: R || s
        let r = session.agg_r.unwrap();
        let r_bytes = r.serialize();
        let mut final_sig = [0u8; 64];
        final_sig[0..32].copy_from_slice(&r_bytes[1..33]); // X-coordinate of R
        final_sig[32..64].copy_from_slice(&s_bytes);

        println!("Final signature R part: {:?}", &final_sig[0..32]);
        println!("Final signature s part: {:?}", &final_sig[32..64]);
        println!("Are you here");

        let sig = Signature::from_slice(&final_sig)?;
        Ok(sig)
    }

    /// Verify a MuSig2 signature against the aggregated public key
    pub fn verify(
        &self,
        session: &MuSig2Session,
        signature: &Signature,
    ) -> Result<bool> {
        if session.agg_r.is_none() || session.challenge.is_none() {
            return Err(anyhow!("Challenge not computed"));
        }

        let xonly_pk = &session.agg_pk.agg_pk.x_only_public_key().0;
        println!("X-only public key: {:?}", xonly_pk);
        println!("Signature: {:?}", signature.serialize());

        let result = self.secp.verify_schnorr(signature, &session.message,  xonly_pk);

        println!(
            "Verify result: {:?}",
            result.is_ok());

        Ok(result.is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_aggregation() {
        let musig = MuSig2::new();

        // Generate two keypairs
        let (sk1, pk1) = musig.generate_keypair();
        let (sk2, pk2) = musig.generate_keypair();

        // Aggregate keys
        let pubkeys = vec![pk1, pk2];
        let agg_key = musig.aggregate_keys(&pubkeys).unwrap();

        // Check that coefficients were computed for each key
        assert!(agg_key.coefficients.contains_key(&pk1));
        assert!(agg_key.coefficients.contains_key(&pk2));
    }

    #[test]
    fn test_signing_and_verification() {
        let musig = MuSig2::new();

        let (sk1, pk1) = musig.generate_keypair();
        let (sk2, pk2) = musig.generate_keypair();

        let pubkeys = vec![pk1, pk2];
        let agg_key = musig.aggregate_keys(&pubkeys).unwrap();

        let nonce1 = musig.generate_nonce();
        let nonce2 = musig.generate_nonce();

        let pub_nonce1 = musig.get_public_nonce(&nonce1);
        let pub_nonce2 = musig.get_public_nonce(&nonce2);

        let message = b"test message";
        let mut session = musig.start_signing_session(
            message,
            agg_key,
            vec![(pk1, pub_nonce1), (pk2, pub_nonce2)],
        );

        musig.compute_challenge(&mut session).unwrap();

        let sig1 = musig.sign(&session, &pk1, &sk1, &nonce1).unwrap();
        let sig2 = musig.sign(&session, &pk2, &sk2, &nonce2).unwrap();

        println!("sig1: {:?}", sig1);
        println!("sig2: {:?}", sig2);

        let agg_sig = musig.aggregate_signatures(&session, &[sig1, sig2]).unwrap();

        println!("Aggregated signature: {:?}", agg_sig.serialize());

        let verification_result = musig.verify(&session, &agg_sig);
        println!("Verification result: {:?}", verification_result);

        assert!(verification_result.unwrap());
    }
}