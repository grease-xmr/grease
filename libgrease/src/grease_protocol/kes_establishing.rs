//! KES channel initialization protocol.
//!
//! This module provides [`KesEstablishing`], which manages the KES's role during
//! channel initialization: validating payload signatures, decrypting encrypted
//! offsets from both channel participants, deriving per-channel keys, and
//! generating proof-of-knowledge proofs.

use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::cryptography::pok::KesPoK;
use crate::cryptography::pok::KesPoKProofs;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::grease_protocol::channel_keys::{kes_channel_keys, ChannelKeyPair, EphemeralChannelId};
use crate::grease_protocol::establish_channel::payload_signature_message;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Bundle of both parties' encrypted offsets, payload signatures, and the ephemeral
/// channel ID for forwarding to the KES.
///
/// The merchant acts as a proxy, collecting both encrypted offsets, payload signatures,
/// associated public data, and the ephemeral channel ID ($\kappa$), then sending them
/// to the KES in a single message.
/// The KES validates the payload signatures before decrypting offsets and deriving
/// the per-channel keypair.
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
    /// The ephemeral channel ID ($\kappa$) encrypted to the KES, used to derive per-channel keys.
    pub ephemeral_channel_id: EphemeralChannelId<KC>,
}

/// Domain separation tag for encrypting offsets to the KES, bound to a specific channel.
///
/// The channel ID is included so that encrypted offsets cannot be replayed across channels.
pub(crate) fn kes_offset_domain(channel_id: &ChannelId) -> String {
    format!("GreaseEncryptToKES-{channel_id}")
}

/// Persistent record stored by the KES after validating an OpenChannel request.
///
/// Corresponds to the `OpenChannel` record defined in Section 4.6.3 of the KES spec.
/// The KES stores this in private/encrypted storage after successfully decrypting
/// offsets and generating proof-of-knowledge proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct OpenChannelRecord<KC: Ciphersuite> {
    /// The channel identifier.
    pub channel_id: ChannelId,
    /// The dispute window duration.
    pub dispute_window: Duration,
    /// Proof-of-knowledge proofs for both parties' offsets.
    pub pok_proofs: KesPoKProofs<KC>,
    /// The merchant's ephemeral public key ($P_m$).
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub merchant_pubkey: KC::G,
    /// The customer's ephemeral public key ($P_c$).
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub customer_pubkey: KC::G,
    /// The merchant's encrypted initial offset ($\chi^M$).
    pub merchant_encrypted_offset: EncryptedSecret<KC>,
    /// The customer's encrypted initial offset ($\chi^C$).
    pub customer_encrypted_offset: EncryptedSecret<KC>,
}

/// Manages the KES's role during channel initialization.
///
/// Created from a validated [`KesInitBundle`] via [`from_bundle`](Self::from_bundle),
/// which verifies payload signatures, decrypts both encrypted offsets, and derives
/// the per-channel keypair. After construction, call [`finalize`](Self::finalize) to
/// generate PoK proofs and the [`OpenChannelRecord`].
///
/// The global KES secret key is consumed during construction and not retained —
/// only the derived per-channel key is stored.
pub struct KesEstablishing<KC: Ciphersuite> {
    channel_id: ChannelId,
    dispute_window: Duration,
    customer_chi: EncryptedSecret<KC>,
    merchant_chi: EncryptedSecret<KC>,
    customer_pubkey: KC::G,
    merchant_pubkey: KC::G,
    /// Per-channel key derived from the ephemeral channel ID (kappa) and the global KES key.
    channel_key: ChannelKeyPair<KC>,
    /// Decrypted offset secrets, kept alive for PoK generation.
    /// Zeroized when this struct is dropped.
    decrypted_offsets: DecryptedOffsets<KC>,
}

impl<KC: Ciphersuite> Drop for KesEstablishing<KC> {
    fn drop(&mut self) {
        self.decrypted_offsets.zeroize();
    }
}

impl<KC: Ciphersuite> std::fmt::Debug for KesEstablishing<KC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KesEstablishing")
            .field("channel_id", &self.channel_id)
            .field("channel_pubkey", &hex::encode(self.channel_key.public.to_bytes().as_ref()))
            .finish_non_exhaustive()
    }
}

impl<KC: Ciphersuite> KesEstablishing<KC> {
    /// Create a `KesEstablishing` instance by validating a [`KesInitBundle`].
    ///
    /// Verifies both parties' payload signatures against their ephemeral public keys,
    /// validates that the encrypted offsets carry the correct role tags, decrypts both
    /// offsets, and derives the per-channel keypair from the ephemeral channel ID.
    ///
    /// The global KES secret key (`kes_secret`) is consumed during this call — it is
    /// used to decrypt offsets and derive the channel key, then dropped (and zeroized
    /// via [`Zeroizing`]).
    pub fn from_bundle(kes_secret: Zeroizing<KC::F>, bundle: KesInitBundle<KC>) -> Result<Self, KesEstablishError> {
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
        // 3. Validate offset roles
        if bundle.customer_encrypted_offset.role() != ChannelRole::Customer {
            return Err(KesEstablishError::WrongRole {
                expected: ChannelRole::Customer,
                got: bundle.customer_encrypted_offset.role(),
            });
        }
        if bundle.merchant_encrypted_offset.role() != ChannelRole::Merchant {
            return Err(KesEstablishError::WrongRole {
                expected: ChannelRole::Merchant,
                got: bundle.merchant_encrypted_offset.role(),
            });
        }

        // 4. Decrypt offsets (requires global KES secret)
        let domain = kes_offset_domain(&bundle.channel_id);
        let customer_secret = bundle.customer_encrypted_offset.decrypt(&*kes_secret, &domain);
        let merchant_secret = bundle.merchant_encrypted_offset.decrypt(&*kes_secret, &domain);
        let decrypted_offsets = DecryptedOffsets { customer: customer_secret, merchant: merchant_secret };

        // 5. Derive per-channel keypair (consumes ephemeral channel ID)
        let channel_key = kes_channel_keys(&*kes_secret, bundle.ephemeral_channel_id);

        // kes_secret is dropped (and zeroized) here at end of scope
        Ok(Self {
            channel_id: bundle.channel_id,
            dispute_window: bundle.dispute_window,
            customer_chi: bundle.customer_encrypted_offset,
            merchant_chi: bundle.merchant_encrypted_offset,
            customer_pubkey: bundle.customer_ephemeral_pubkey,
            merchant_pubkey: bundle.merchant_ephemeral_pubkey,
            channel_key,
            decrypted_offsets,
        })
    }

    /// The per-channel public key ($P_g$).
    pub fn channel_public_key(&self) -> &KC::G {
        &self.channel_key.public
    }

    /// Generate proof-of-knowledge for both parties' decrypted offsets.
    ///
    /// The KES proves it knows each party's decrypted offset AND the per-channel private
    /// key $k_g$, using bound [`KesPoK`] proofs.
    pub fn generate_pok<R: RngCore + CryptoRng>(&self, rng: &mut R) -> KesPoKProofs<KC> {
        let customer_pok = KesPoK::<KC>::prove(rng, self.decrypted_offsets.customer.secret(), &self.channel_key.secret);
        let merchant_pok = KesPoK::<KC>::prove(rng, self.decrypted_offsets.merchant.secret(), &self.channel_key.secret);
        KesPoKProofs { customer_pok, merchant_pok }
    }

    /// Generate proof-of-knowledge and produce an [`OpenChannelRecord`] for persistent storage.
    ///
    /// This implements the `validateOpen` algorithm from Section 4.6.3 of the KES spec:
    /// the KES generates PoK proofs, then builds the `OpenChannel` record containing
    /// the proofs and encrypted offsets (for future force-close/dispute flows).
    pub fn finalize<R: RngCore + CryptoRng>(&self, rng: &mut R) -> (KesPoKProofs<KC>, OpenChannelRecord<KC>) {
        let pok_proofs = self.generate_pok(rng);

        let record = OpenChannelRecord {
            channel_id: self.channel_id.clone(),
            dispute_window: self.dispute_window,
            pok_proofs: pok_proofs.clone(),
            merchant_pubkey: self.merchant_pubkey,
            customer_pubkey: self.customer_pubkey,
            merchant_encrypted_offset: self.merchant_chi.clone(),
            customer_encrypted_offset: self.customer_chi.clone(),
        };

        (pok_proofs, record)
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
    #[error("Expected offset from {expected} but got {got}")]
    WrongRole { expected: ChannelRole, got: ChannelRole },
    #[error("Payload signature verification failed for {role}")]
    InvalidPayloadSignature { role: ChannelRole },
}
