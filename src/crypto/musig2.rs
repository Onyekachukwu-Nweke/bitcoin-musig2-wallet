use secp256k1_zkp::{self, PublicKey, SecretKey, Message, Secp256k1, schnorr::Signature};
use bitcoin::hashes::{sha256, Hash, HashEngine};
use rand::rngs::OsRng;
use std::collections::HashMap;
use anyhow::{anyhow, Result};

/// MuSig2 key aggregation coefficient
/// Calculated as the hash of L||X_i where L is the multiset of all public keys.
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

        let mut agg_pk = None;
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
        let msg = Message::from_slice(message).expect("32 bytes");

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
        let mut agg_r = None;

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
        session.challenge = Some(challenge);

        Ok(())
    }

    /// Create a partial signature for a participant
    pub fn sign(
        &self,
        session: &MuSig2Session,
        pubkey: &PublicKey,
        seckey: &SecretKey,
        nonce: &SecretNonce,
    ) -> Result<Signature> {
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
        let k_i1 = nonce.k1.clone();
        let mut k_i2_b = nonce.k2.clone();
        k_i2_b.mul_assign(&b)?;

        let mut k_i = k_i1.clone();
        k_i.add_assign(&k_i2_b)?;

        // Next: e*a_i*x_i
        let mut e_ai = e.clone();
        e_ai.mul_assign(&a_i)?;
        let mut e_ai_xi = seckey.clone();
        e_ai_xi.mul_assign(&e_ai)?;

        // Finally: s_i = k_i + e*a_i*x_i
        let mut s_i = k_i;
        s_i.add_assign(&e_ai_xi)?;

        // Create signature
        let sig = Signature::from_slice(&s_i[..])?;

        Ok(sig)
    }

    /// Aggregate partial signatures into a final signature
    pub fn aggregate_signatures(
        &self,
        session: &MuSig2Session,
        partial_sigs: &[Signature],
    ) -> Result<Signature> {
        if session.agg_r.is_none() || session.challenge.is_none() {
            return Err(anyhow!("Challenge not computed"));
        }

        if partial_sigs.is_empty() {
            return Err(anyhow!("No partial signatures to aggregate"));
        }

        // In MuSig2, signature aggregation is a simple sum: s = ∑s_i
        let mut s = [0u8; 32];

        for sig in partial_sigs {
            let sig_bytes = sig.serialize_compact();

            // Add signature scalar to our running sum (mod curve order)
            let sig_scalar = SecretKey::from_slice(&sig_bytes[..])?;
            let s_scalar = SecretKey::from_slice(&s)?;

            let mut result = s_scalar;
            result.add_assign(&sig_scalar)?;

            s.copy_from_slice(&result[..]);
        }

        // The final signature is (R, s) where R is the aggregated nonce
        // For Schnorr in Bitcoin, this is encoded as r || s
        // However, here we're just returning s since R is stored in the session

        let sig = Signature::from_slice(&s)?;

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

        // Extract R and s from signature
        let r = session.agg_r.unwrap();
        let s = signature.serialize_compact();

        // Convert to secp signature format (r || s)
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(&r.serialize()[1..33]);  // Remove the prefix byte
        sig_bytes[32..64].copy_from_slice(&s);

        let schnorr_sig = Signature::from_slice(&sig_bytes)?;

        // Verify the signature
        let result = self.secp.verify_schnorr(&session.message, &schnorr_sig, &session.agg_pk.agg_pk);

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

        // Generate keypairs
        let (sk1, pk1) = musig.generate_keypair();
        let (sk2, pk2) = musig.generate_keypair();

        // Aggregate keys
        let pubkeys = vec![pk1, pk2];
        let agg_key = musig.aggregate_keys(&pubkeys).unwrap();

        // Generate nonces
        let nonce1 = musig.generate_nonce();
        let nonce2 = musig.generate_nonce();

        let pub_nonce1 = musig.get_public_nonce(&nonce1);
        let pub_nonce2 = musig.get_public_nonce(&nonce2);

        // Create signing session
        let message = b"test message";
        let mut session = musig.start_signing_session(
            message,
            agg_key,
            vec![(pk1, pub_nonce1), (pk2, pub_nonce2)],
        );

        // Compute challenge
        musig.compute_challenge(&mut session).unwrap();

        // Create partial signatures
        let sig1 = musig.sign(&session, &pk1, &sk1, &nonce1).unwrap();
        let sig2 = musig.sign(&session, &pk2, &sk2, &nonce2).unwrap();

        // Aggregate signatures
        let agg_sig = musig.aggregate_signatures(&session, &[sig1, sig2]).unwrap();

        // Verify signature
        assert!(musig.verify(&session, &agg_sig).unwrap());
    }
}