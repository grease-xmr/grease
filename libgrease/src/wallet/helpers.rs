//! Persistence for scanned wallet outputs, including the migration off monero-wallet 0.1's layout.

use monero_oxide::io::{read_byte, read_bytes, read_u32, write_byte, VarInt};
use monero_wallet::WalletOutput;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};
use std::io::{self, Read, Write};

/// Serialize `Vec<WalletOutput>` as a sequence of byte arrays.
/// Uses `WalletOutput::write` to serialize each output.
pub fn serialize_outputs<S>(outputs: &Vec<WalletOutput>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = s.serialize_seq(Some(outputs.len()))?;
    for output in outputs {
        let buf = output.serialize();
        seq.serialize_element(&buf)?;
    }
    seq.end()
}

/// Deserialize `Vec<WalletOutput>` from a sequence of byte arrays.
/// Uses [`read_output`] to deserialize each output, so blobs written before the monero-oxide swap still load.
pub fn deserialize_outputs<'de, D>(de: D) -> Result<Vec<WalletOutput>, D::Error>
where
    D: Deserializer<'de>,
{
    let byte_vec: Vec<Vec<u8>> = Vec::deserialize(de)?;
    byte_vec.into_iter().map(|b| read_output(&mut b.as_slice()).map_err(serde::de::Error::custom)).collect()
}

/// Read one persisted [`WalletOutput`], advancing `blob` past the record.
///
/// monero-wallet 0.2 changed two fields of the (explicitly non-protocol) `WalletOutput` encoding, so blobs
/// grease wrote before the monero-oxide swap no longer parse. Both changes are positionally unambiguous, so
/// this reads the current layout first and falls back to rewriting the old one — see
/// [`upgrade_legacy_output`]. Nothing has to be re-derived from the chain.
///
/// The two layouts are not self-describing, so the fallback is decided by whether the current reader succeeds.
/// An old record is one field-width out of alignment from the second field onwards, which all but guarantees
/// an invalid key or a non-canonical scalar, but it is a probabilistic discrimination rather than a tagged one.
pub fn read_output(blob: &mut &[u8]) -> io::Result<WalletOutput> {
    let mut current = *blob;
    if let Ok(output) = WalletOutput::read(&mut current) {
        *blob = current;
        return Ok(output);
    }

    let mut legacy = *blob;
    let mut upgraded = Vec::with_capacity(blob.len() + 4);
    upgrade_legacy_output(&mut legacy, &mut upgraded)?;
    let output = WalletOutput::read(&mut upgraded.as_slice())?;
    *blob = legacy;
    Ok(output)
}

/// Read a run of concatenated [`WalletOutput`] records, in either layout.
pub fn read_outputs(mut blob: &[u8]) -> io::Result<Vec<WalletOutput>> {
    let mut outputs = Vec::new();
    while !blob.is_empty() {
        outputs.push(read_output(&mut blob)?);
    }
    Ok(outputs)
}

/// Rewrite one `WalletOutput` record from the monero-wallet 0.1 layout into the 0.2 layout.
///
/// Exactly two fields moved, and everything around them is byte-identical:
///
/// | Field | 0.1 | 0.2 |
/// | --- | --- | --- |
/// | `AbsoluteId.index_in_transaction` | `u32` little-endian | `u64` little-endian |
/// | `Metadata.arbitrary_data` chunk count | `u32` little-endian | varint |
///
/// Everything else — the transaction hash, `RelativeId`, `OutputData` (32-byte compressed key, 32-byte scalar,
/// 40-byte `Commitment`), the timelock varint, the subaddress and payment-id options, and the chunks
/// themselves — is copied through untouched.
fn upgrade_legacy_output<R: Read>(r: &mut R, w: &mut Vec<u8>) -> io::Result<()> {
    // AbsoluteId: the transaction hash is unchanged, the index widens.
    w.write_all(&read_bytes::<_, 32>(r)?)?;
    w.write_all(&u64::from(read_u32(r)?).to_le_bytes())?;

    // RelativeId and OutputData: one u64, a 32-byte key, a 32-byte scalar and a 40-byte commitment, all
    // unchanged.
    copy_exact(r, w, 8 + 32 + 32 + 40)?;

    // Metadata, up to the chunk count. Each of these is unchanged but variable-width, so the record has to be
    // parsed this far to find the count.
    let additional_timelock = <u64 as VarInt>::read(r)?;
    VarInt::write(&additional_timelock, w)?;
    if copy_flag(r, w)? {
        // SubaddressIndex: account and index, a u32 each.
        copy_exact(r, w, 8)?;
    }
    if copy_flag(r, w)? {
        // PaymentId: a one-byte kind marker and eight bytes of id.
        copy_exact(r, w, 9)?;
    }

    // The chunk count is the field that changed framing.
    let chunks = read_u32(r)?;
    VarInt::write(&chunks, w)?;
    (0..chunks).try_for_each(|_| {
        let len = read_byte(r)?;
        write_byte(&len, w)?;
        copy_exact(r, w, usize::from(len))
    })
}

/// Copy an `Option`'s one-byte discriminant through, reporting whether a value follows.
fn copy_flag<R: Read>(r: &mut R, w: &mut Vec<u8>) -> io::Result<bool> {
    let flag = read_byte(r)?;
    if flag > 1 {
        return Err(io::Error::other("invalid option discriminant in a legacy wallet output"));
    }
    write_byte(&flag, w)?;
    Ok(flag == 1)
}

/// Copy `len` bytes through verbatim.
fn copy_exact<R: Read>(r: &mut R, w: &mut Vec<u8>, len: usize) -> io::Result<()> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    w.write_all(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `WalletOutput` in the current layout, assembled field by field so the test does not depend on having
    /// scanned a chain. `arbitrary_data` carries two chunks so the count reframing is actually exercised.
    ///
    /// The key is the Ed25519 basepoint and the scalars are small, which keeps the encoding canonical.
    fn current_layout(index_in_transaction: u64, chunks: &[&[u8]]) -> Vec<u8> {
        use ciphersuite::group::{Group, GroupEncoding};

        let mut blob = Vec::new();
        blob.extend_from_slice(&[7u8; 32]); // transaction hash
        blob.extend_from_slice(&index_in_transaction.to_le_bytes());
        blob.extend_from_slice(&42u64.to_le_bytes()); // index_on_blockchain
        blob.extend_from_slice(crate::XmrPoint::generator().to_bytes().as_ref()); // key
        blob.extend_from_slice(&crate::XmrScalar::from(9u64).to_bytes()); // key_offset
        blob.extend_from_slice(&crate::XmrScalar::from(3u64).to_bytes()); // commitment mask
        blob.extend_from_slice(&1_000u64.to_le_bytes()); // commitment amount
        blob.push(0); // additional_timelock: varint 0, i.e. Timelock::None
        blob.push(0); // subaddress: None
        blob.push(0); // payment_id: None
        VarInt::write(&u32::try_from(chunks.len()).unwrap(), &mut blob).unwrap();
        for chunk in chunks {
            blob.push(u8::try_from(chunk.len()).unwrap());
            blob.extend_from_slice(chunk);
        }
        blob
    }

    /// The same output as monero-wallet 0.1 would have written it: a `u32` index and a `u32` chunk count.
    fn legacy_layout(index_in_transaction: u32, chunks: &[&[u8]]) -> Vec<u8> {
        let current = current_layout(u64::from(index_in_transaction), chunks);
        let mut blob = Vec::new();
        blob.extend_from_slice(&current[..32]);
        blob.extend_from_slice(&index_in_transaction.to_le_bytes());
        // Everything from `index_on_blockchain` to the chunk count is unchanged; the count is the last field
        // before the chunks, and this fixture's metadata is three single bytes wide.
        let tail = 8 + 32 + 32 + 40 + 3;
        blob.extend_from_slice(&current[40..40 + tail]);
        blob.extend_from_slice(&u32::try_from(chunks.len()).unwrap().to_le_bytes());
        let chunk_start = 40 + tail + u32::try_from(chunks.len()).unwrap().varint_len();
        blob.extend_from_slice(&current[chunk_start..]);
        blob
    }

    #[test]
    fn a_legacy_output_reads_back_identically() {
        [(0u32, &[][..]), (1, &[]), (300_000, &[&b"grease"[..], &b"channel"[..]])].into_iter().for_each(
            |(index, chunks)| {
                let expected = WalletOutput::read(&mut current_layout(u64::from(index), chunks).as_slice())
                    .expect("the current-layout fixture parses");

                let legacy = legacy_layout(index, chunks);
                let mut cursor = legacy.as_slice();
                let migrated = read_output(&mut cursor).expect("the legacy blob upgrades");

                assert_eq!(migrated, expected);
                assert!(cursor.is_empty(), "the whole legacy record was consumed");
                // Re-writing through `WalletOutput::write` produces the current layout, so a migrated output
                // round-trips from then on.
                assert_eq!(migrated.serialize(), current_layout(u64::from(index), chunks));
            },
        );
    }

    #[test]
    fn a_current_output_is_read_without_migration() {
        let blob = current_layout(1, &[&b"grease"[..]]);
        let mut cursor = blob.as_slice();
        let output = read_output(&mut cursor).expect("the current layout parses");
        assert!(cursor.is_empty());
        assert_eq!(output.serialize(), blob);
    }

    #[test]
    fn concatenated_records_are_peeled_one_at_a_time() {
        let mut blob = current_layout(1, &[]);
        blob.extend_from_slice(&legacy_layout(2, &[&b"x"[..]]));
        let outputs = read_outputs(&blob).expect("both records read");
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].index_in_transaction(), 1);
        assert_eq!(outputs[1].index_in_transaction(), 2);
    }

    #[test]
    fn a_truncated_record_is_an_error() {
        let blob = legacy_layout(1, &[]);
        assert!(read_output(&mut &blob[..blob.len() - 2]).is_err());
    }
}
