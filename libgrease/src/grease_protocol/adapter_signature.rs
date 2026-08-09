use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::Curve25519Secret;
use crate::grease_protocol::update_record::CloseHash;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use ciphersuite::Ed25519;
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

/// Domain-separation tag for the adapter-signature message. Versioned: a layout change gets a new tag.
///
/// Distinct from [`UPDATE_RECORD_DST`][crate::grease_protocol::update_record::UPDATE_RECORD_DST] by design: a
/// completed (adapted) closing signature is an ordinary Schnorr signature, so the message it signs must never
/// collide with the message the update-record signatures sign.
pub const ADAPTER_SIG_DST: &[u8] = b"Grease AdapterSig v2";

/// The transcript-based commitment message an adapter signature signs for state `update_count`.
///
/// Binds `(channel_id, update_count, close_hash)`, where `close_hash` is the canonical closing-transaction hash
/// the state's [`UpdateRecord`][crate::grease_protocol::update_record::UpdateRecord] commits to (sourced from
/// [`commitment_tx_message`][crate::wallet::multisig_wallet::commitment_tx_message]). Anyone holding an update
/// record can therefore recompute this message from the record's own fields.
pub fn adapter_signature_message(channel_id: &ChannelId, update_count: u64, close_hash: &CloseHash) -> Vec<u8> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    let mut transcript = DigestTranscript::<Blake2b512>::new(ADAPTER_SIG_DST);
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    transcript.append_message(b"update_count", update_count.to_le_bytes());
    transcript.append_message(b"close_hash", close_hash.as_bytes());
    transcript.challenge(b"adapter_sig_message").to_vec()
}

pub trait AdapterSignatureHandler: HasRole {
    /// Assign the initial adapter signature offset.
    fn initialize_signature_offset(&mut self);

    /// Update the adapter signature offset.
    ///
    /// Implementations that need to store the offset should clone it and then
    /// call `zeroize()` on their copy when it's no longer needed.
    fn update_signature_offset(&mut self, offset: &XmrScalar);

    /// Return the current adapter signature offset.
    fn adapter_signature_offset(&self) -> &XmrScalar;

    /// Generate a new adapter signature over the closing transaction of state `update_count`, using the current
    /// secret key and offset. The message is [`adapter_signature_message`].
    fn new_adapter_signature<R: RngCore + CryptoRng>(
        &self,
        secret_key: &Curve25519Secret,
        channel_id: &ChannelId,
        update_count: u64,
        close_hash: &CloseHash,
        rng: &mut R,
    ) -> Result<AdaptedSignature<Ed25519>, AdapterSignatureError> {
        let offset = self.adapter_signature_offset();
        let msg = adapter_signature_message(channel_id, update_count, close_hash);
        Ok(AdaptedSignature::<Ed25519>::sign(secret_key.as_scalar(), offset, msg, rng))
    }
}

#[derive(Debug, Error)]
pub enum AdapterSignatureError {
    #[error("Could not provide result because the following information is missing: {0}")]
    MissingInformation(String),
}
