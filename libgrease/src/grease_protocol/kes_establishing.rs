//! KES channel initialization protocol.
//!
//! This module provides [`KesEstablishing`], a lightweight struct that manages
//! the KES's role during channel initialization: receiving encrypted offsets
//! from both channel participants, decrypting them, and generating
//! proof-of-knowledge proofs.

use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::cryptography::pok::KesPoK;
use crate::cryptography::pok::KesPoKProofs;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::grease_protocol::channel_keys::{self, ChannelKeyPair, EphemeralChannelId};
use crate::grease_protocol::establish_channel::payload_signature_message;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Bundle of both parties' encrypted offsets and payload signatures for forwarding to the KES.
///
/// The merchant acts as a proxy, collecting both encrypted offsets, payload signatures,
/// and associated public data, then sending them to the KES in a single message.
/// The KES validates the payload signatures before decrypting offsets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KesInitBundle<KC: Ciphersuite> {
    pub channel_id: ChannelId,
    pub dispute_window: Duration,
    // Customer's data
    pub customer_encrypted_offset: EncryptedSecret<KC>,
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub customer_t0: KC::G,
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub customer_ephemeral_pubkey: KC::G,
    pub customer_payload_sig: SchnorrSignature<KC>,
    // Merchant's data
    pub merchant_encrypted_offset: EncryptedSecret<KC>,
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub merchant_t0: KC::G,
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub merchant_ephemeral_pubkey: KC::G,
    pub merchant_payload_sig: SchnorrSignature<KC>,
}

/// Domain separation tag for encrypting offsets to the KES, bound to a specific channel.
///
/// The channel ID is included so that encrypted offsets cannot be replayed across channels.
pub(crate) fn kes_offset_domain(channel_id: &ChannelId) -> String {
    format!("GreaseEncryptToKES-{channel_id}")
}

/// Manages the KES's role during channel initialization.
///
/// The KES receives encrypted offsets (chi values) from both the customer and
/// merchant, decrypts them using its private key, and can then produce
/// proof-of-knowledge proofs demonstrating it holds the decrypted values.
pub struct KesEstablishing<KC: Ciphersuite> {
    kes_secret: Zeroizing<KC::F>,
    kes_public: KC::G,
    channel_id: Option<ChannelId>,
    customer_chi: Option<EncryptedSecret<KC>>,
    merchant_chi: Option<EncryptedSecret<KC>>,
}

impl<KC: Ciphersuite> std::fmt::Debug for KesEstablishing<KC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KesEstablishing")
            .field("kes_public", &hex::encode(self.kes_public.to_bytes().as_ref()))
            .finish_non_exhaustive()
    }
}

impl<KC: Ciphersuite> KesEstablishing<KC> {
    /// Create a new KES establishing instance from a KES keypair.
    pub fn new(kes_secret: Zeroizing<KC::F>, kes_public: KC::G) -> Self {
        Self { kes_secret, kes_public, channel_id: None, customer_chi: None, merchant_chi: None }
    }

    /// The KES public key.
    pub fn public_key(&self) -> &KC::G {
        &self.kes_public
    }

    /// Set the channel ID for domain-separated offset decryption.
    ///
    /// This is set automatically by [`receive_bundle`](Self::receive_bundle). Use this method
    /// when providing offsets individually via [`receive_customer_offset`](Self::receive_customer_offset)
    /// and [`receive_merchant_offset`](Self::receive_merchant_offset).
    pub fn set_channel_id(&mut self, channel_id: ChannelId) {
        self.channel_id = Some(channel_id);
    }

    /// Store the customer's encrypted offset.
    pub fn receive_customer_offset(&mut self, chi: EncryptedSecret<KC>) -> Result<(), KesEstablishError> {
        if chi.role() != ChannelRole::Customer {
            return Err(KesEstablishError::WrongRole { expected: ChannelRole::Customer, got: chi.role() });
        }
        self.customer_chi = Some(chi);
        Ok(())
    }

    /// Store the merchant's encrypted offset.
    pub fn receive_merchant_offset(&mut self, chi: EncryptedSecret<KC>) -> Result<(), KesEstablishError> {
        if chi.role() != ChannelRole::Merchant {
            return Err(KesEstablishError::WrongRole { expected: ChannelRole::Merchant, got: chi.role() });
        }
        self.merchant_chi = Some(chi);
        Ok(())
    }

    /// Returns `true` if offsets from both parties have been received.
    pub fn has_both_offsets(&self) -> bool {
        self.customer_chi.is_some() && self.merchant_chi.is_some()
    }

    /// Receive both encrypted offsets at once from a [`KesInitBundle`], validating
    /// payload signatures before storing the offsets.
    ///
    /// The dispute window is validated implicitly: it is bound into the payload
    /// signature message, so a mismatch will cause signature verification to fail.
    pub fn receive_bundle(&mut self, bundle: KesInitBundle<KC>) -> Result<(), KesEstablishError> {
        // 1. Verify customer payload signature
        let customer_msg = payload_signature_message::<KC>(
            &bundle.channel_id,
            &bundle.customer_encrypted_offset,
            bundle.dispute_window,
            &bundle.customer_t0,
        );
        if !bundle.customer_payload_sig.verify(&bundle.customer_ephemeral_pubkey, &customer_msg) {
            return Err(KesEstablishError::InvalidPayloadSignature { role: ChannelRole::Customer });
        }
        // 2. Verify merchant payload signature
        let merchant_msg = payload_signature_message::<KC>(
            &bundle.channel_id,
            &bundle.merchant_encrypted_offset,
            bundle.dispute_window,
            &bundle.merchant_t0,
        );
        if !bundle.merchant_payload_sig.verify(&bundle.merchant_ephemeral_pubkey, &merchant_msg) {
            return Err(KesEstablishError::InvalidPayloadSignature { role: ChannelRole::Merchant });
        }
        // 3. Store channel ID and offsets
        self.channel_id = Some(bundle.channel_id);
        self.receive_customer_offset(bundle.customer_encrypted_offset)?;
        self.receive_merchant_offset(bundle.merchant_encrypted_offset)?;
        Ok(())
    }

    /// Decrypt the stored offsets and return the plaintext secrets.
    ///
    /// Both offsets must have been received via `receive_customer_offset` and
    /// `receive_merchant_offset` before calling this method.
    pub fn decrypt_offsets(&self) -> Result<DecryptedOffsets<KC>, KesEstablishError> {
        let channel_id = self.channel_id.as_ref().ok_or(KesEstablishError::MissingChannelId)?;
        let customer_chi = self.customer_chi.as_ref().ok_or(KesEstablishError::MissingOffset(ChannelRole::Customer))?;
        let merchant_chi = self.merchant_chi.as_ref().ok_or(KesEstablishError::MissingOffset(ChannelRole::Merchant))?;
        let domain = kes_offset_domain(channel_id);
        let customer_secret = customer_chi.decrypt(&self.kes_secret, &domain);
        let merchant_secret = merchant_chi.decrypt(&self.kes_secret, &domain);
        Ok(DecryptedOffsets { customer: customer_secret, merchant: merchant_secret })
    }

    /// Decrypt offsets and generate proof-of-knowledge for both parties.
    ///
    /// The KES proves it knows each party's decrypted offset AND its own private key,
    /// using bound [`KesPoK`] proofs. The decrypted secrets are zeroized after proof generation.
    pub fn generate_pok<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<KesPoKProofs<KC>, KesEstablishError> {
        let mut offsets = self.decrypt_offsets()?;
        let customer_pok = KesPoK::<KC>::prove(rng, offsets.customer.secret(), &self.kes_secret);
        let merchant_pok = KesPoK::<KC>::prove(rng, offsets.merchant.secret(), &self.kes_secret);
        offsets.zeroize();
        Ok(KesPoKProofs { customer_pok, merchant_pok })
    }

    /// Derive a unique channel keypair from an ephemeral channel ID.
    ///
    /// The KES uses its private key and the encrypted shared secret from the party
    /// to derive a per-channel keypair `(kg, Pg)` as specified in Section 4.4 of the white paper.
    /// The ephemeral secret is consumed and zeroized by `kes_channel_keys`.
    pub fn derive_channel_keys(&self, ephemeral_id: EphemeralChannelId<KC>) -> ChannelKeyPair<KC> {
        channel_keys::kes_channel_keys(&*self.kes_secret, ephemeral_id)
    }
}

/// Decrypted offset secrets from both channel participants.
#[derive(Debug)]
pub struct DecryptedOffsets<KC: Ciphersuite> {
    customer: SecretWithRole<KC>,
    merchant: SecretWithRole<KC>,
}

impl<KC: Ciphersuite> Zeroize for DecryptedOffsets<KC> {
    fn zeroize(&mut self) {
        self.customer.zeroize();
        self.merchant.zeroize();
    }
}

impl<KC: Ciphersuite> DecryptedOffsets<KC> {
    /// The customer's decrypted offset secret.
    pub fn customer(&self) -> &SecretWithRole<KC> {
        &self.customer
    }

    /// The merchant's decrypted offset secret.
    pub fn merchant(&self) -> &SecretWithRole<KC> {
        &self.merchant
    }
}

#[derive(Debug, Error)]
pub enum KesEstablishError {
    #[error("Channel ID not set — call receive_bundle or set_channel_id before decrypting")]
    MissingChannelId,
    #[error("Missing offset from {0}")]
    MissingOffset(ChannelRole),
    #[error("Expected offset from {expected} but got {got}")]
    WrongRole { expected: ChannelRole, got: ChannelRole },
    #[error("Payload signature verification failed for {role}")]
    InvalidPayloadSignature { role: ChannelRole },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::Ed25519;
    use dalek_ff_group::{EdwardsPoint, Scalar as EdScalar};
    use modular_frost::curve::{Field, Group};
    use std::str::FromStr;
    use subtle::ConstantTimeEq;

    fn test_channel_id() -> ChannelId {
        ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap()
    }

    #[test]
    fn encrypt_decrypt_offsets_round_trip() {
        let mut rng = rand_core::OsRng;
        let channel_id = test_channel_id();

        // KES keypair
        let kes_secret = EdScalar::random(&mut rng);
        let kes_public = EdwardsPoint::generator() * &kes_secret;

        // Random offsets for each party
        let customer_scalar = EdScalar::random(&mut rng);
        let merchant_scalar = EdScalar::random(&mut rng);
        let customer_secret = SecretWithRole::new(customer_scalar, ChannelRole::Customer);
        let merchant_secret = SecretWithRole::new(merchant_scalar, ChannelRole::Merchant);

        // Encrypt to KES using the channel-bound domain tag
        let domain = kes_offset_domain(&channel_id);
        let customer_enc = EncryptedSecret::<Ed25519>::encrypt(customer_secret.clone(), &kes_public, &mut rng, &domain);
        let merchant_enc = EncryptedSecret::<Ed25519>::encrypt(merchant_secret.clone(), &kes_public, &mut rng, &domain);

        // Feed into KesEstablishing and decrypt
        let mut kes = KesEstablishing::<Ed25519>::new(Zeroizing::new(kes_secret), kes_public);
        kes.set_channel_id(channel_id);
        kes.receive_customer_offset(customer_enc).unwrap();
        kes.receive_merchant_offset(merchant_enc).unwrap();

        let offsets = kes.decrypt_offsets().unwrap();
        assert_eq!(offsets.customer().secret().ct_eq(&customer_scalar).unwrap_u8(), 1);
        assert_eq!(offsets.merchant().secret().ct_eq(&merchant_scalar).unwrap_u8(), 1);
    }

    #[test]
    fn decrypt_offsets_rejects_wrong_channel_id() {
        let mut rng = rand_core::OsRng;
        let channel_id = test_channel_id();
        let wrong_channel_id =
            ChannelId::from_str("XGCaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

        // KES keypair
        let kes_secret = EdScalar::random(&mut rng);
        let kes_public = EdwardsPoint::generator() * &kes_secret;

        // Encrypt with the real channel ID
        let domain = kes_offset_domain(&channel_id);
        let customer_scalar = EdScalar::random(&mut rng);
        let customer_enc = EncryptedSecret::<Ed25519>::encrypt(
            SecretWithRole::new(customer_scalar, ChannelRole::Customer),
            &kes_public,
            &mut rng,
            &domain,
        );
        let merchant_enc = EncryptedSecret::<Ed25519>::encrypt(
            SecretWithRole::new(EdScalar::random(&mut rng), ChannelRole::Merchant),
            &kes_public,
            &mut rng,
            &domain,
        );

        // Decrypt with a different channel ID — domain mismatch should produce wrong values
        let mut kes = KesEstablishing::<Ed25519>::new(Zeroizing::new(kes_secret), kes_public);
        kes.set_channel_id(wrong_channel_id);
        kes.receive_customer_offset(customer_enc).unwrap();
        kes.receive_merchant_offset(merchant_enc).unwrap();

        let offsets = kes.decrypt_offsets().unwrap();
        assert_eq!(
            offsets.customer().secret().ct_eq(&customer_scalar).unwrap_u8(),
            0,
            "Decryption with wrong channel ID should not recover the original scalar"
        );
    }

    #[test]
    fn decrypt_offsets_requires_channel_id() {
        let mut rng = rand_core::OsRng;
        let kes_secret = EdScalar::random(&mut rng);
        let kes_public = EdwardsPoint::generator() * &kes_secret;
        let kes = KesEstablishing::<Ed25519>::new(Zeroizing::new(kes_secret), kes_public);

        let err = kes.decrypt_offsets().unwrap_err();
        assert!(matches!(err, KesEstablishError::MissingChannelId), "got: {err:?}");
    }
}
