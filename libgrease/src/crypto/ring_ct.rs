use crate::crypto::hashes::{HashToPoint, HashToScalar};

pub trait RingCT {
    type SecretKey;
    type PublicKey;
    type Signature;
    type Decoy;
    type Error;
    type Context;
    type HashToScalar: HashToScalar;
    type HashToPoint: HashToPoint;

    async fn sign(
        &self,
        spend_key: &Self::SecretKey,
        message: &[u8],
        decoys: &[Self::Decoy],
        ctx: &mut Self::Context,
    ) -> Result<Self::Signature, Self::Error>;

    async fn verify(
        &self,
        public_key: &Self::PublicKey,
        key_image: &Self::PublicKey,
        message: &[u8],
        ring: &[Self::Decoy],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error>;
}

/// A trait for fetching decoys in a ring signature context.
///
/// Some implementations require a lot of state to return decoys. For instance, a real blockchain implementation
/// will need a way to communicate with a node, a random number generator and so on. This can all be bundled into
/// the [`Self::Context`] type and passed to [`fetch_decoys`].
pub trait FetchDecoys {
    type Context;
    type Output;
    type Decoy;
    type Error;

    async fn fetch_decoys(
        &self,
        ring_len: usize,
        input: Self::Output,
        context: &mut Self::Context,
    ) -> Result<Vec<Self::Decoy>, Self::Error>;
}
