use secp256k1_zkp::{self, PublicKey, SecretKey, Message, Secp256k1, schnorr::Signature};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use rand::rngs::OsRng;
use std::collections::HashMap;
use anyhow::{anyhow, Result};
use serde::Serialize;

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
        // First, compute the commitment hash b = H(L||R_1^(1)||...||R_n^(1)||m)
        let mut hasher = sha256::Hash::engine();

        // Add all first nonce points R_i1 in sorted order
        let mut sorted_nonce_points = Vec::new();
        for (_, nonce) in &session.public_nonces {
            sorted_nonce_points.push(nonce.r1.serialize());
        }
        sorted_nonce_points.sort();

        for r1_serialized in sorted_nonce_points {
            hasher.input(&r1_serialized);
        }

        // Add the message
        hasher.input(&session.message[..]);

        println!("Session message: {:?}", session.message);

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

        let final_r = agg_r.unwrap();

        // Store the aggregated R
        session.agg_r = Some(final_r);

        // Get x-only public key for challenge calculation
        let (xonly_pk, _) = session.agg_pk.agg_pk.x_only_public_key();

        // Compute the Schnorr challenge e = H(R||P||m)
        // Where R and P are x-only (32-byte) public keys
        let mut challenge_hasher = sha256::Hash::engine();

        // Extract the x-coordinate of R (32 bytes)
        let (xonly_r, _) = final_r.x_only_public_key();
        let r_bytes = xonly_r.serialize();
        challenge_hasher.input(&r_bytes);

        // Use the x-only public key P
        let pk_bytes = xonly_pk.serialize();
        challenge_hasher.input(&pk_bytes);

        // Add the message
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

        // Add all first nonce points R_i1 in sorted order
        let mut sorted_nonce_points = Vec::new();
        for (_, n) in &session.public_nonces {
            sorted_nonce_points.push(n.r1.serialize());
        }
        sorted_nonce_points.sort();

        for r1_serialized in sorted_nonce_points {
            hasher.input(&r1_serialized);
        }

        hasher.input(&session.message[..]);

        println!("Session message: {:?}", session.message);

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

        // Next: e*a_i
        let e_ai = e.mul_tweak(&a_i.into())?;

        // Then: e*a_i*x_i
        let e_ai_xi = seckey.mul_tweak(&e_ai.into())?;

        // Finally: s_i = k_i + e*a_i*x_i
        let s_i = k_i.add_tweak(&e_ai_xi.into())?;

        // Extract the 32-byte array from the SecretKey
        Ok(s_i.secret_bytes())
    }

    /// Aggregate partial signatures into a final signature
    pub fn aggregate_signatures(
        &self,
        session: &MuSig2Session,
        partial_sigs: &[[u8; 32]],
    ) -> Result<Signature> {
        if session.agg_r.is_none() || session.challenge.is_none() {
            return Err(anyhow!("Challenge not computed"));
        }

        if partial_sigs.is_empty() {
            return Err(anyhow!("No partial signatures to aggregate"));
        }

        // Add all partial signatures together
        // Initialize s with the first partial signature
        let mut s = SecretKey::from_slice(&partial_sigs[0])?;

        // Print each partial signature
        for (i, sig) in partial_sigs.iter().enumerate() {
            println!("Debug: Partial Signature {} = {:?}", i, sig);
        }

        // Add the rest of the partial signatures
        for sig in &partial_sigs[1..] {
            let next_s = SecretKey::from_slice(sig)?;
            s = s.add_tweak(&next_s.into())?;
        }

        // Get the R value from the session
        let r = session.agg_r.unwrap();

        // Get the x-only representation of R
        let (xonly_r, _) = r.x_only_public_key();

        // Construct full Schnorr signature (R || s)
        let r_bytes = xonly_r.serialize();
        let s_bytes = s.secret_bytes();

        // Combine into the final signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&r_bytes);
        println!("Sig bytes: {:?}", sig_bytes);
        sig_bytes[32..64].copy_from_slice(&s_bytes);
        println!("Sig bytes 2: {:?}", sig_bytes);

        // Create the signature from the combined bytes
        let signature = Signature::from_slice(&sig_bytes)?;

        Ok(signature)
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

        // Print debug values before verification
        println!("Debug: Aggregated Public Key = {:?}", session.agg_pk.agg_pk);
        println!("Debug: Aggregated R Value = {:?}", session.agg_r);
        println!("Debug: Message = {:?}", session.message);
        println!("Debug: Signature = {:?}", signature);

        // Get the x-only public key for verification
        let (xonly_pk, _) = session.agg_pk.agg_pk.x_only_public_key();

        println!("Session message: {:?}", session.message);

        // Verify the Schnorr signature
        let result = self.secp.verify_schnorr(signature, &session.message, &xonly_pk);

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

        let agg_sig = musig.aggregate_signatures(&session, &[sig1, sig2]).unwrap();

        let verification_result = musig.verify(&session, &agg_sig);
        println!("{:?}", verification_result);
        assert!(verification_result.unwrap());
    }
}