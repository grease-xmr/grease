use crate::channel_id::{ChannelId, ProvisionalChannelIdError};
use crate::grease_protocol::update_record::CloseHash;
use crate::payment_channel::HasRole;
use crate::XmrScalar;
use thiserror::Error;

/// Domain-separation tag for the adapter-signature message. Versioned: a layout change gets a new tag.
///
/// Distinct from [`UPDATE_RECORD_DST`][crate::grease_protocol::update_record::UPDATE_RECORD_DST] by design: a
/// completed (adapted) closing signature is an ordinary Schnorr signature, so the message it signs must never
/// collide with the message the update-record signatures sign.
pub const ADAPTER_SIG_DST: &[u8] = b"Grease AdapterSig v2";

/// The transcript-based commitment message an adapter signature signs for state `update_count`.
///
/// Binds `(channel_id, update_count, close_hash)`, where `close_hash` is the **per-holder** hash of the
/// commitment transaction this signature authorizes broadcasting, from
/// [`commitment_tx_message`][crate::wallet::multisig_wallet::commitment_tx_message].
///
/// It is *not* a field of the state's [`UpdateRecord`][crate::grease_protocol::update_record::UpdateRecord]: a
/// record carries one hash per state and each party holds its own closing transaction, so what the record commits
/// to is the hash of the *pair*
/// ([`commitment_pair_message`][crate::wallet::multisig_wallet::commitment_pair_message]). A holder recomputes
/// this message from the record's `(channel_id, update_count)` plus the state's two balances, and the record's
/// pair hash — over those same two balances — is what validates them.
///
/// A provisional (`XGT…`) id is refused: a completed (adapted) signature over this message is an ordinary
/// Schnorr signature a peer will verify and act on, so the message must never come into existence over an id
/// that commits to no funding output. A `Result` rather than an assertion, because both the signing and the
/// verifying side of the exchange pass through here and verification runs on peer input in release builds.
pub fn adapter_signature_message(
    channel_id: &ChannelId,
    update_count: u64,
    close_hash: &CloseHash,
) -> Result<Vec<u8>, ProvisionalChannelIdError> {
    use blake2::Blake2b512;
    use flexible_transcript::{DigestTranscript, Transcript};

    channel_id.require_finalized()?;
    let mut transcript = DigestTranscript::<Blake2b512>::new(ADAPTER_SIG_DST);
    transcript.append_message(b"channel_id", channel_id.as_str().as_bytes());
    transcript.append_message(b"update_count", update_count.to_le_bytes());
    transcript.append_message(b"close_hash", close_hash.as_bytes());
    Ok(transcript.challenge(b"adapter_sig_message").to_vec())
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
}

#[derive(Debug, Error)]
pub enum AdapterSignatureError {
    #[error("Could not provide result because the following information is missing: {0}")]
    MissingInformation(String),
    #[error(transparent)]
    ProvisionalChannelId(#[from] ProvisionalChannelIdError),
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
        adapter_signature_message(&id, 7, &CloseHash::new([0xaa; 64])).expect("a final id yields a message")
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
        assert_ne!(adapter_signature_message(&other_id, 7, &CloseHash::new([0xaa; 64])).unwrap(), base);
        assert_ne!(adapter_signature_message(&id, 8, &CloseHash::new([0xaa; 64])).unwrap(), base);
        assert_ne!(adapter_signature_message(&id, 7, &CloseHash::new([0xab; 64])).unwrap(), base);
    }

    /// F2 of the K-20 review: an adapted signature completes into an ordinary Schnorr signature, so its message
    /// must be refused — not silently produced — over a provisional (`XGT…`) id.
    #[test]
    fn a_provisional_channel_id_yields_no_message() {
        let provisional = ChannelId::from_str(&CHANNEL_ID.replace("XGC", "XGT")).expect("valid provisional id");
        let err = adapter_signature_message(&provisional, 7, &CloseHash::new([0xaa; 64]))
            .expect_err("a provisional id must be refused");
        assert_eq!(err.0, provisional);
    }
}
