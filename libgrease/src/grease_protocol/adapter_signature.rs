use crate::channel_id::ChannelId;
use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::keys::Curve25519Secret;
use crate::grease_protocol::update_record::CloseHash;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use crate::Ed25519;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grease_protocol::update_record::CloseHash;
    use std::str::FromStr;

    /// The frozen channel id from `channel_id.rs`'s own known-answer vector, so this vector depends on no
    /// derivation but the one under test.
    const CHANNEL_ID: &str = "XGC0845ec076e64984475627c8c1a154defceaeea2ce3cd39c55b02823b4f70a4";

    fn fixed_message() -> Vec<u8> {
        let id = ChannelId::from_str(CHANNEL_ID).expect("valid channel id");
        adapter_signature_message(&id, 7, &CloseHash::new([0xaa; 64]))
    }

    /// Freezes the adapter-signature message under the live `"Grease AdapterSig v2"` domain tag.
    ///
    /// This was the one `flexible-transcript` site in the crate without a known-answer vector. It crosses
    /// `DigestTranscript`'s member tagging and little-endian length prefixes and `blake2`'s `Blake2b512`, so a
    /// drift here means a pre-signature produced on one revision no longer verifies against one produced on
    /// another.
    /// The value is stated over the pre-swap `DigestTranscript` framing: it was cross-checked against an
    /// independent model of that framing, which reproduces the `commitment_tx_message` vector K-24 froze on the
    /// old pin. So this pins the old behaviour rather than rubber-stamping the new.
    #[test]
    fn adapter_signature_message_is_frozen() {
        const ADAPTER_SIG_V2: &str = concat!(
            "a07115834d098c18bc2e9a97c9cdff81a17bba27c97346dcef32bee47d953624",
            "e2c5b78f01e8b62416cd9a3eb930a23b955442bf6c813dc7915d1fa03d283233",
        );
        assert_eq!(hex::encode(fixed_message()), ADAPTER_SIG_V2);
    }

    /// All three absorbed fields separate the message, so a pre-signature cannot be replayed at another state
    /// or against another closing transaction.
    #[test]
    fn adapter_signature_message_binds_each_absorbed_field() {
        let id = ChannelId::from_str(CHANNEL_ID).expect("valid channel id");
        let other_id = ChannelId::from_str(&CHANNEL_ID.replace("XGC0", "XGC1")).expect("valid channel id");
        let base = fixed_message();
        assert_ne!(adapter_signature_message(&other_id, 7, &CloseHash::new([0xaa; 64])), base);
        assert_ne!(adapter_signature_message(&id, 8, &CloseHash::new([0xaa; 64])), base);
        assert_ne!(adapter_signature_message(&id, 7, &CloseHash::new([0xab; 64])), base);
    }
}
