//! A digest bound that carries a minimum output size.
//!
//! `flexible-transcript` 0.3.4 deleted its own `SecureDigest` and relaxed `DigestTranscript<D>` to plain
//! `D: Send + Clone + Digest`. Grease still needs the "at least 32 bytes of output" guarantee that trait
//! carried, because [`ChannelIdMetadata`](crate::channel_id::ChannelIdMetadata) truncates a digest to exactly
//! 32 bytes and is only sound when the digest is at least that wide. (The `SharedPublicKey` commitment in
//! [`crate::grease_protocol::multisig_wallet`] used to be the second such place; it now keeps the whole
//! 64-byte `Blake2b512` challenge and no longer truncates.)
//!
//! So the trait is re-declared here rather than replaced with plain [`Digest`].

use digest::consts::U32;
use digest::typenum::{IsGreaterOrEqual, True};
use digest::{Digest, HashMarker, OutputSizeUser};

/// A cryptographic digest with at least a 256-bit output, and so at least a 128-bit security level.
///
/// Blanket-implemented: any [`Digest`] whose output is 32 bytes or wider qualifies, and one narrower than
/// that fails to satisfy the bound at compile time.
pub trait SecureDigest: Digest + HashMarker {}

impl<D> SecureDigest for D
where
    D: Digest + HashMarker,
    <D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>,
{
}
