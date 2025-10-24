use crate::crypto::keys::Curve25519PublicKey;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
pub use dalek_ff_group::{EdwardsPoint as XmrPoint, Scalar as XmrScalar};
use modular_frost::curve::PrimeField;
use monero::consensus::encode::Error as MoneroError;
use monero::consensus::{ReadExt, WriteExt};
use std::io::{self, Read, Write};

pub fn write_group_element<C: Ciphersuite, W: Write>(w: &mut W, element: &C::G) -> io::Result<()> {
    let b = element.to_bytes();
    w.emit_u64(b.as_ref().len() as u64)?;
    w.emit_slice(b.as_ref())
}

pub fn write_field_element<C: Ciphersuite, W: Write>(w: &mut W, element: &C::F) -> io::Result<()> {
    let b = element.to_repr();
    w.emit_u64(b.as_ref().len() as u64)?;
    w.emit_slice(b.as_ref())
}

pub fn read_group_element<C: Ciphersuite, R: Read>(reader: &mut R) -> Result<C::G, MoneroError> {
    let len = reader.read_u64()? as usize;
    let mut buf = <<C as Ciphersuite>::G as GroupEncoding>::Repr::default();
    if buf.as_ref().len() != len {
        return Err(MoneroError::ParseFailed("Invalid group element length".into()));
    }
    reader.read_exact(buf.as_mut())?;
    let elem =
        C::G::from_bytes(&buf).into_option().ok_or_else(|| MoneroError::ParseFailed("Invalid group element".into()))?;
    Ok(elem)
}

pub fn read_field_element<C: Ciphersuite, R: Read>(reader: &mut R) -> Result<C::F, MoneroError> {
    let len = reader.read_u64()? as usize;
    let mut buf = <<C as Ciphersuite>::F as PrimeField>::Repr::default();
    if buf.as_ref().len() != len {
        return Err(MoneroError::ParseFailed("Invalid field element length".into()));
    }
    reader.read_exact(buf.as_mut())?;
    let elem =
        C::F::from_repr(buf).into_option().ok_or_else(|| MoneroError::ParseFailed("Invalid field element".into()))?;
    Ok(elem)
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
