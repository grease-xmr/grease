//! KES encryption functions implementing the EncryptMessage and DecryptMessage algorithms.
//!
//! This module provides curve-agnostic encryption for scalar values using ephemeral ECDH key exchange.
//! See the KES specification (`docs/src/40_kes.typ`) for the algorithm details.

use crate::error::ReadError;
use crate::grease_protocol::utils::{read_field_element, read_group_element, write_field_element, write_group_element};
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use zeroize::Zeroize;

/// Domain separator for KES encryption hash function.
const KES_ENCRYPT_DOMAIN: &[u8] = b"MessageEncrypt";

/// An encrypted scalar value using ephemeral ECDH key exchange.
///
/// Implements the KES `EncryptMessage` and `DecryptMessage` algorithms from the KES specification.
/// The encryption uses a random nonce `r` to compute a shared secret with the recipient's
/// public key, then masks the message scalar with this shared secret.
#[derive(Clone, Debug)]
pub struct EncryptedScalar<C: Ciphersuite> {
    /// R = r * G - the public nonce used for ECDH
    pub nonce: C::G,
    /// chi = (m + s) mod N - the encrypted scalar where s is the shared secret
    pub chi: C::F,
}

impl<C: Ciphersuite> EncryptedScalar<C> {
    /// Encrypt a scalar message using the recipient's public key.
    ///
    /// Implements the `EncryptMessage` algorithm:
    /// 1. Generate random nonzero scalar `r`
    /// 2. Compute `R = r * G` (public nonce)
    /// 3. Compute shared secret point `P_s = r * P`
    /// 4. Compute `s = H2F("MessageEncrypt", P_s)`
    /// 5. Compute `chi = m + s`
    /// 6. Zeroize `r`
    /// 7. Return `(R, chi)`
    pub fn encrypt<R: RngCore + CryptoRng>(message: &C::F, recipient_pubkey: &C::G, rng: &mut R) -> Self {
        let mut r = C::random_nonzero_F(rng);
        let nonce = C::generator() * r;
        let shared_point = *recipient_pubkey * r;
        let shared_secret = C::hash_to_F(KES_ENCRYPT_DOMAIN, shared_point.to_bytes().as_ref());
        let chi = *message + shared_secret;
        r.zeroize();
        Self { nonce, chi }
    }

    /// Decrypt the encrypted scalar using the recipient's private key.
    ///
    /// Implements the `DecryptMessage` algorithm:
    /// 1. Compute shared secret point `P_s = k * R`
    /// 2. Compute `s = H2F("MessageEncrypt", P_s)`
    /// 3. Compute `m = chi - s`
    /// 4. Return `m`
    pub fn decrypt(&self, recipient_private_key: &C::F) -> C::F {
        let shared_point = self.nonce * *recipient_private_key;
        let shared_secret = C::hash_to_F(KES_ENCRYPT_DOMAIN, shared_point.to_bytes().as_ref());
        self.chi - shared_secret
    }

    /// Deserialize an `EncryptedScalar` from a reader.
    ///
    /// Returns an error if the nonce is the identity element (which would make
    /// the encryption trivially insecure).
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let nonce =
            read_group_element::<C, R>(reader).map_err(|e| ReadError::new("EncryptedScalar.nonce", e.to_string()))?;
        if nonce.is_identity().into() {
            return Err(ReadError::new(
                "EncryptedScalar.nonce",
                "nonce cannot be the identity element".to_string(),
            ));
        }
        let chi =
            read_field_element::<C, R>(reader).map_err(|e| ReadError::new("EncryptedScalar.chi", e.to_string()))?;
        Ok(Self { nonce, chi })
    }
}

impl<C: Ciphersuite> Writable for EncryptedScalar<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        write_group_element::<C, W>(writer, &self.nonce)?;
        write_field_element::<C, W>(writer, &self.chi)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ed25519;
    use grease_babyjubjub::BabyJubJub;

    #[test]
    fn encrypt_decrypt_roundtrip_ed25519() {
        let mut rng = rand_core::OsRng;
        let private_key = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let public_key = Ed25519::generator() * private_key;
        let message = <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let encrypted = EncryptedScalar::<Ed25519>::encrypt(&message, &public_key, &mut rng);
        let decrypted = encrypted.decrypt(&private_key);

        assert_eq!(message, decrypted);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_babyjubjub() {
        let mut rng = rand_core::OsRng;
        let private_key = <BabyJubJub as Ciphersuite>::random_nonzero_F(&mut rng);
        let public_key = BabyJubJub::generator() * private_key;
        let message = <BabyJubJub as Ciphersuite>::F::random(&mut rng);

        let encrypted = EncryptedScalar::<BabyJubJub>::encrypt(&message, &public_key, &mut rng);
        let decrypted = encrypted.decrypt(&private_key);

        assert_eq!(message, decrypted);
    }

    #[test]
    fn decrypt_with_wrong_key_produces_wrong_result() {
        let mut rng = rand_core::OsRng;
        let private_key = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let wrong_key = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let public_key = Ed25519::generator() * private_key;
        let message = <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let encrypted = EncryptedScalar::<Ed25519>::encrypt(&message, &public_key, &mut rng);
        let decrypted = encrypted.decrypt(&wrong_key);

        assert_ne!(message, decrypted);
    }

    #[test]
    fn serialization_roundtrip() {
        let mut rng = rand_core::OsRng;
        let private_key = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let public_key = Ed25519::generator() * private_key;
        let message = <Ed25519 as Ciphersuite>::F::random(&mut rng);

        let encrypted = EncryptedScalar::<Ed25519>::encrypt(&message, &public_key, &mut rng);
        let serialized = encrypted.serialize();
        let deserialized = EncryptedScalar::<Ed25519>::read(&mut &serialized[..]).unwrap();

        let decrypted = deserialized.decrypt(&private_key);
        assert_eq!(message, decrypted);
    }

    #[test]
    fn reject_identity_nonce_on_deserialization() {
        use ciphersuite::group::Group;

        let mut rng = rand_core::OsRng;
        // Create an encrypted scalar with identity nonce manually
        let chi = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let identity_nonce = <Ed25519 as Ciphersuite>::G::identity();
        let malformed = EncryptedScalar::<Ed25519> { nonce: identity_nonce, chi };

        let serialized = malformed.serialize();
        let result = EncryptedScalar::<Ed25519>::read(&mut &serialized[..]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("identity"));
    }
}
