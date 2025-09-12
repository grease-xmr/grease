use crate::crypto::keys::Curve25519PublicKey;
use ciphersuite::group::{Group, GroupEncoding};
pub use dalek_ff_group::{EdwardsPoint as XmrPoint, Scalar as XmrScalar};
use modular_frost::curve::{Curve, PrimeField};
use monero::consensus::WriteExt;
use std::io::Write;

pub fn write_group_element<C: Curve, W: Write>(w: &mut W, element: &C::G) -> std::io::Result<()> {
    let b = element.to_bytes();
    w.emit_u64(b.as_ref().len() as u64)?;
    w.emit_slice(b.as_ref())
}

pub fn write_field_element<C: Curve, W: Write>(w: &mut W, element: &C::F) -> std::io::Result<()> {
    let b = element.to_repr();
    w.emit_u64(b.as_ref().len() as u64)?;
    w.emit_slice(b.as_ref())
}

/// Verify that my witness, shard and the peer's shard combine to the multisig wallet spend key.
pub fn verify_shards(
    public_keys: &[Curve25519PublicKey],
    witness: &XmrScalar,
    my_shard: &XmrScalar,
    kes_shard: &XmrPoint,
) -> bool {
    let lhs = XmrPoint::generator() * (*witness + my_shard) + kes_shard;
    let zero = XmrPoint::identity();
    let rhs = public_keys.iter().fold(zero, |tot, x| tot + x.as_point());
    lhs == rhs
}
