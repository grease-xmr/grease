use crate::error::ReadError;
use crate::grease_protocol::utils::{write_field_element, write_group_element};
use ciphersuite::group::ff::Field;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use crate::cryptography::ciphersuite_ext::hash_to_F;
use crate::io::Writable;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Read;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct SchnorrPoK<C: Ciphersuite> {
    pub_nonce: C::G,
    s: C::F,
}

impl<C: Ciphersuite> SchnorrPoK<C> {
    fn challenge(pub_nonce: &C::G, pub_key: &C::G, binding: &[u8]) -> C::F {
        let msg = [pub_nonce.to_bytes().as_ref(), pub_key.to_bytes().as_ref(), binding].concat();
        hash_to_F::<C>(b"SchnorrPoK", &msg)
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

impl<C: Ciphersuite> Serialize for SchnorrPoK<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = Writable::serialize(self);
        serializer.serialize_str(&hex::encode(bytes))
    }
}

impl<'de, C: Ciphersuite> Deserialize<'de> for SchnorrPoK<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        SchnorrPoK::<C>::read(&mut &bytes[..]).map_err(|e| serde::de::Error::custom(format!("{e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::Group;
    use crate::Ed25519;
    use ciphersuite::WrappedGroup;

    #[test]
    fn schnorr_pok_on_ed25519() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let public_key = Ed25519::generator() * secret;
        let binding = b"test-context";
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding);
        assert!(pok.verify(&public_key, binding));
        let invalid_pubkey = public_key + Ed25519::generator();
        assert!(!pok.verify(&invalid_pubkey, binding));
    }

    #[test]
    fn schnorr_pok_rejects_identity_public_key() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let identity = <Ed25519 as WrappedGroup>::G::identity();
        assert!(!pok.verify(&identity, &[]), "verification must reject identity public key");
    }

    #[test]
    fn schnorr_pok_with_zero_secret() {
        let mut rng = rand_core::OsRng;
        let zero = <Ed25519 as WrappedGroup>::F::ZERO;
        let public_key = Ed25519::generator() * zero; // identity
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
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let public_key = Ed25519::generator() * secret;
        let binding = b"roundtrip-test";
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding);
        let data = Writable::serialize(&pok);
        let deserialized = SchnorrPoK::<Ed25519>::read(&mut &data[..]).unwrap();
        assert!(deserialized.verify(&public_key, binding));
    }

    #[test]
    fn schnorr_pok_proofs_are_non_deterministic() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let public_key = Ed25519::generator() * secret;
        let pok1 = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let pok2 = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        // Both should verify
        assert!(pok1.verify(&public_key, &[]));
        assert!(pok2.verify(&public_key, &[]));
        // But they should be different (different nonces)
        let data1 = Writable::serialize(&pok1);
        let data2 = Writable::serialize(&pok2);
        assert_ne!(data1, data2, "proofs must use fresh nonces and produce different outputs");
    }

    #[test]
    fn schnorr_pok_read_rejects_identity_nonce() {
        // Manually construct a proof with identity nonce
        let identity = <Ed25519 as WrappedGroup>::G::identity();
        let s = <Ed25519 as WrappedGroup>::F::random(&mut rand_core::OsRng);
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
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, &[]);
        let data = Writable::serialize(&pok);
        // Truncate the data
        let truncated = &data[..data.len() / 2];
        let result = SchnorrPoK::<Ed25519>::read(&mut &truncated[..]);
        assert!(result.is_err(), "deserialization must fail on truncated data");
    }

    #[test]
    fn schnorr_pok_binding_mismatch_fails() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let public_key = Ed25519::generator() * secret;
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
        let secret = <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let binding_a = b"context-a";
        let binding_b = b"context-b";
        // Use a deterministic "rng" by capturing state - actually we can't easily do this,
        // but we can verify that the same secret with different bindings produces proofs
        // that only verify with their respective bindings
        let pok_a = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding_a);
        let pok_b = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret, binding_b);
        let public_key = Ed25519::generator() * secret;
        // Each proof should only verify with its own binding
        assert!(pok_a.verify(&public_key, binding_a));
        assert!(!pok_a.verify(&public_key, binding_b));
        assert!(pok_b.verify(&public_key, binding_b));
        assert!(!pok_b.verify(&public_key, binding_a));
    }

    #[test]
    fn challenge_differs_for_different_inputs() {
        let mut rng = rand_core::OsRng;
        let g = Ed25519::generator();
        let nonce1 = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let nonce2 = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let pk1 = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let pk2 = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);
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
        let nonce = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);
        let pk = g * <Ed25519 as WrappedGroup>::F::random(&mut rng);

        let c1 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, b"binding-1");
        let c2 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, b"binding-2");
        let c3 = SchnorrPoK::<Ed25519>::challenge(&nonce, &pk, &[]);

        assert_ne!(c1, c2, "different bindings must produce different challenges");
        assert_ne!(c1, c3, "non-empty vs empty binding must produce different challenges");
        assert_ne!(c2, c3);
    }

}
