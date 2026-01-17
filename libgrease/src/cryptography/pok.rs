use crate::error::ReadError;
use crate::grease_protocol::utils::{write_field_element, write_group_element};
use ciphersuite::group::ff::Field;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use log::*;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use zeroize::Zeroize;

pub struct KesPoK<C: Ciphersuite> {
    pub shard_pok: SchnorrPoK<C>,
    pub private_key_pok: SchnorrPoK<C>,
}

impl<C: Ciphersuite> KesPoK<C> {
    /// Compute the binding data that ties both proofs together.
    ///
    /// This includes both public keys so that each proof is bound to the other,
    /// preventing proof mixing attacks.
    fn binding(shard_pubkey: &C::G, kes_pubkey: &C::G) -> Vec<u8> {
        [shard_pubkey.to_bytes().as_ref(), kes_pubkey.to_bytes().as_ref()].concat()
    }

    /// Prove that the possessor of `private_key` knows `shard`.
    ///
    /// Both proofs are cryptographically bound together via both public keys
    /// included in each challenge computation.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, shard: &C::F, private_key: &C::F) -> Self {
        let shard_pubkey = C::generator() * shard;
        let kes_pubkey = C::generator() * private_key;
        let binding = Self::binding(&shard_pubkey, &kes_pubkey);
        let shard_pok = SchnorrPoK::<C>::prove(rng, shard, &binding);
        let private_key_pok = SchnorrPoK::<C>::prove(rng, private_key, &binding);
        Self { shard_pok, private_key_pok }
    }

    pub fn verify(&self, shard_pubkey: &C::G, kes_pubkey: &C::G) -> bool {
        let binding = Self::binding(shard_pubkey, kes_pubkey);
        let pk_valid = self.private_key_pok.verify(kes_pubkey, &binding);
        let result_pk = if pk_valid { "KES knows the private key" } else { "KES does NOT know the private key" };
        let shard_valid = self.shard_pok.verify(shard_pubkey, &binding);
        let result_shard = if shard_valid { "KES knows the shard value" } else { "KES does NOT know the shard value" };
        let result = pk_valid && shard_valid;
        if result {
            debug!("VALID: {result_pk} AND {result_shard}");
        } else {
            warn!("INVALID KES PoK verification: {result_pk} AND {result_shard}");
        };
        result
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let shard_pok = SchnorrPoK::<C>::read(reader)?;
        let private_key_pok = SchnorrPoK::<C>::read(reader)?;
        Ok(Self { shard_pok, private_key_pok })
    }
}

impl<C: Ciphersuite> Writable for KesPoK<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.shard_pok.write(writer)?;
        self.private_key_pok.write(writer)?;
        Ok(())
    }
}

pub struct SchnorrPoK<C: Ciphersuite> {
    pub_nonce: C::G,
    s: C::F,
}

impl<C: Ciphersuite> SchnorrPoK<C> {
    fn challenge(pub_nonce: &C::G, pub_key: &C::G, binding: &[u8]) -> C::F {
        let msg = [pub_nonce.to_bytes().as_ref(), pub_key.to_bytes().as_ref(), binding].concat();
        C::hash_to_F(b"SchnorrPoK", &msg)
    }

    /// Prove knowledge of `secret` with optional binding data included in the challenge.
    ///
    /// The `binding` parameter allows including additional context in the challenge hash,
    /// which cryptographically binds this proof to that context. This prevents proof
    /// reuse across different contexts and enables binding multiple proofs together.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, secret: &C::F, binding: &[u8]) -> Self {
        let mut nonce = C::F::random(rng);
        let pub_nonce = C::generator() * nonce;
        let pub_key = C::generator() * secret;
        let s = nonce + *secret * Self::challenge(&pub_nonce, &pub_key, binding);
        nonce.zeroize();
        Self { pub_nonce, s }
    }

    /// Verify the proof against `public_key` with the same `binding` used during proving.
    ///
    /// The `binding` must match exactly what was used in `prove()`, otherwise
    /// verification will fail.
    pub fn verify(&self, public_key: &C::G, binding: &[u8]) -> bool {
        // Reject identity public key - would allow trivial forgery
        if public_key.is_identity().into() {
            return false;
        }
        let lhs = C::generator() * self.s;
        let rhs = self.pub_nonce + *public_key * Self::challenge(&self.pub_nonce, public_key, binding);
        lhs == rhs
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let pub_nonce = crate::grease_protocol::utils::read_group_element::<C, R>(reader)
            .map_err(|e| ReadError::new("SchnorrPoK.pub_nonce", e.to_string()))?;
        if pub_nonce.is_identity().into() {
            return Err(ReadError::new(
                "SchnorrPoK.pub_nonce",
                "public nonce cannot be the identity element".to_string(),
            ));
        }
        let s = crate::grease_protocol::utils::read_field_element::<C, R>(reader)
            .map_err(|e| ReadError::new("SchnorrPoK.s", e.to_string()))?;
        Ok(Self { pub_nonce, s })
    }
}

impl<C: Ciphersuite> Writable for SchnorrPoK<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        write_group_element::<C, W>(writer, &self.pub_nonce)?;
        write_field_element::<C, W>(writer, &self.s)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::Group;
    use ciphersuite::Ed25519;

    #[test]
    fn schnorr_pok_on_ed25519() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let public_key = Ed25519::generator() * &secret;
        let binding = b"test-context";
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding);
        assert!(pok.verify(&public_key, binding));
        let invalid_pubkey = public_key + Ed25519::generator();
        assert!(!pok.verify(&invalid_pubkey, binding));
    }

    #[test]
    fn kes_pok_on_ed25519() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let sigma_pubkey = Ed25519::generator() * &shard;
        let kes_pubkey = Ed25519::generator() * &private_key;
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        assert!(pok.verify(&sigma_pubkey, &kes_pubkey));
        let data = pok.serialize();
        let pok = KesPoK::<Ed25519>::read(&mut &data[..]).unwrap();
        assert!(pok.verify(&sigma_pubkey, &kes_pubkey));
        let invalid_kes_pubkey = kes_pubkey + Ed25519::generator();
        assert!(!pok.verify(&sigma_pubkey, &invalid_kes_pubkey));
    }

    #[test]
    fn schnorr_pok_rejects_identity_public_key() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let identity = <Ed25519 as Ciphersuite>::G::identity();
        assert!(!pok.verify(&identity, &[]), "verification must reject identity public key");
    }

    #[test]
    fn schnorr_pok_with_zero_secret() {
        let mut rng = rand_core::OsRng;
        let zero = <Ed25519 as Ciphersuite>::F::ZERO;
        let public_key = Ed25519::generator() * &zero; // identity
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &zero, &[]);
        // Zero secret produces identity public key, which should be rejected
        assert!(
            !pok.verify(&public_key, &[]),
            "zero secret yields identity pubkey which must be rejected"
        );
    }

    #[test]
    fn schnorr_pok_serialization_roundtrip() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let public_key = Ed25519::generator() * &secret;
        let binding = b"roundtrip-test";
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding);
        let data = pok.serialize();
        let deserialized = SchnorrPoK::<Ed25519>::read(&mut &data[..]).unwrap();
        assert!(deserialized.verify(&public_key, binding));
    }

    #[test]
    fn schnorr_pok_proofs_are_non_deterministic() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let public_key = Ed25519::generator() * &secret;
        let pok1 = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let pok2 = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        // Both should verify
        assert!(pok1.verify(&public_key, &[]));
        assert!(pok2.verify(&public_key, &[]));
        // But they should be different (different nonces)
        let data1 = pok1.serialize();
        let data2 = pok2.serialize();
        assert_ne!(data1, data2, "proofs must use fresh nonces and produce different outputs");
    }

    #[test]
    fn schnorr_pok_read_rejects_identity_nonce() {
        // Manually construct a proof with identity nonce
        let identity = <Ed25519 as Ciphersuite>::G::identity();
        let s = <Ed25519 as Ciphersuite>::F::random(&mut rand_core::OsRng);
        let mut data = Vec::new();
        write_group_element::<Ed25519, _>(&mut data, &identity).unwrap();
        write_field_element::<Ed25519, _>(&mut data, &s).unwrap();
        let result = SchnorrPoK::<Ed25519>::read(&mut &data[..]);
        assert!(result.is_err(), "deserialization must reject identity nonce");
        let err = result.err().unwrap();
        assert!(
            err.to_string().contains("identity"),
            "error message should mention identity: {err}"
        );
    }

    #[test]
    fn schnorr_pok_read_rejects_truncated_data() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let data = pok.serialize();
        // Truncate the data
        let truncated = &data[..data.len() / 2];
        let result = SchnorrPoK::<Ed25519>::read(&mut &truncated[..]);
        assert!(result.is_err(), "deserialization must fail on truncated data");
    }

    #[test]
    fn schnorr_pok_binding_mismatch_fails() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let public_key = Ed25519::generator() * &secret;
        let binding_a = b"context-a";
        let binding_b = b"context-b";
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding_a);
        assert!(pok.verify(&public_key, binding_a), "proof should verify with correct binding");
        assert!(!pok.verify(&public_key, binding_b), "proof must fail with wrong binding");
        assert!(
            !pok.verify(&public_key, &[]),
            "proof must fail with empty binding when created with non-empty"
        );
    }

    #[test]
    fn schnorr_pok_different_bindings_produce_different_proofs() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let binding_a = b"context-a";
        let binding_b = b"context-b";
        // Use a deterministic "rng" by capturing state - actually we can't easily do this,
        // but we can verify that the same secret with different bindings produces proofs
        // that only verify with their respective bindings
        let pok_a = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding_a);
        let pok_b = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding_b);
        let public_key = Ed25519::generator() * &secret;
        // Each proof should only verify with its own binding
        assert!(pok_a.verify(&public_key, binding_a));
        assert!(!pok_a.verify(&public_key, binding_b));
        assert!(pok_b.verify(&public_key, binding_b));
        assert!(!pok_b.verify(&public_key, binding_a));
    }

    #[test]
    fn kes_pok_invalid_shard_pubkey() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let sigma_pubkey = Ed25519::generator() * &shard;
        let kes_pubkey = Ed25519::generator() * &private_key;
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        // Valid verification
        assert!(pok.verify(&sigma_pubkey, &kes_pubkey));
        // Invalid shard pubkey
        let invalid_sigma = sigma_pubkey + Ed25519::generator();
        assert!(!pok.verify(&invalid_sigma, &kes_pubkey), "must reject invalid shard pubkey");
    }

    #[test]
    fn kes_pok_swapped_pubkeys_must_fail() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let sigma_pubkey = Ed25519::generator() * &shard;
        let kes_pubkey = Ed25519::generator() * &private_key;
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        // Swapping pubkeys should fail (unless shard == private_key by chance)
        if shard != private_key {
            assert!(
                !pok.verify(&kes_pubkey, &sigma_pubkey),
                "swapped pubkeys must fail verification"
            );
        }
    }

    #[test]
    fn kes_pok_identity_pubkeys_rejected() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let sigma_pubkey = Ed25519::generator() * &shard;
        let kes_pubkey = Ed25519::generator() * &private_key;
        let identity = <Ed25519 as Ciphersuite>::G::identity();
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        assert!(!pok.verify(&identity, &kes_pubkey), "identity shard pubkey must be rejected");
        assert!(!pok.verify(&sigma_pubkey, &identity), "identity kes pubkey must be rejected");
        assert!(!pok.verify(&identity, &identity), "both identity pubkeys must be rejected");
    }

    #[test]
    fn kes_pok_read_rejects_truncated_data() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        let data = pok.serialize();
        // Truncate to only contain partial second proof
        let truncated = &data[..data.len() - 10];
        let result = KesPoK::<Ed25519>::read(&mut &truncated[..]);
        assert!(result.is_err(), "deserialization must fail on truncated data");
    }

    #[test]
    fn challenge_differs_for_different_inputs() {
        let mut rng = rand_core::OsRng;
        let g = Ed25519::generator();
        let nonce1 = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let nonce2 = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pk1 = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pk2 = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let binding = b"test";

        let c1 = SchnorrPoK::<Ed25519>::challenge(&nonce1, &pk1, binding);
        let c2 = SchnorrPoK::<Ed25519>::challenge(&nonce2, &pk1, binding);
        let c3 = SchnorrPoK::<Ed25519>::challenge(&nonce1, &pk2, binding);
        let c4 = SchnorrPoK::<Ed25519>::challenge(&nonce2, &pk2, binding);

        // All challenges should be distinct
        assert_ne!(c1, c2, "different nonces must produce different challenges");
        assert_ne!(c1, c3, "different pubkeys must produce different challenges");
        assert_ne!(c1, c4);
        assert_ne!(c2, c3);
        assert_ne!(c2, c4);
        assert_ne!(c3, c4);
    }

    #[test]
    fn challenge_differs_for_different_bindings() {
        let mut rng = rand_core::OsRng;
        let g = Ed25519::generator();
        let nonce = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pk = g * <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let c1 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, b"binding-1");
        let c2 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, b"binding-2");
        let c3 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, &[]);

        assert_ne!(c1, c2, "different bindings must produce different challenges");
        assert_ne!(c1, c3, "non-empty vs empty binding must produce different challenges");
        assert_ne!(c2, c3);
    }

    #[test]
    fn kes_pok_proofs_are_bound_together() {
        // This test verifies that the two proofs in KesPoK cannot be mixed from different sources.
        // Since both proofs include both public keys in their challenge, extracting one proof
        // and combining it with another proof (from a different KesPoK) should fail verification.
        let mut rng = rand_core::OsRng;

        // Create two different KesPoK instances
        let shard1 = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pk1 = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let shard2 = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let pk2 = <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let pok1 = KesPoK::<Ed25519>::prove(&mut rng, &shard1, &pk1);
        let pok2 = KesPoK::<Ed25519>::prove(&mut rng, &shard2, &pk2);

        let shard1_pubkey = Ed25519::generator() * &shard1;
        let kes1_pubkey = Ed25519::generator() * &pk1;
        let shard2_pubkey = Ed25519::generator() * &shard2;
        let kes2_pubkey = Ed25519::generator() * &pk2;

        // Valid verifications
        assert!(pok1.verify(&shard1_pubkey, &kes1_pubkey));
        assert!(pok2.verify(&shard2_pubkey, &kes2_pubkey));

        // Create a mixed proof by combining parts from different KesPoKs
        let mixed_pok = KesPoK::<Ed25519> {
            shard_pok: SchnorrPoK::<Ed25519>::read(&mut &pok1.shard_pok.serialize()[..]).unwrap(),
            private_key_pok: SchnorrPoK::<Ed25519>::read(&mut &pok2.private_key_pok.serialize()[..]).unwrap(),
        };

        // Mixed proof should fail because the binding (both pubkeys) won't match
        assert!(
            !mixed_pok.verify(&shard1_pubkey, &kes2_pubkey),
            "mixed proof must fail: shard1 proof was bound to (shard1, kes1), not (shard1, kes2)"
        );
        assert!(
            !mixed_pok.verify(&shard2_pubkey, &kes1_pubkey),
            "mixed proof must fail: pk2 proof was bound to (shard2, kes2), not (shard2, kes1)"
        );
    }
}
