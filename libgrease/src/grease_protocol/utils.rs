use crate::error::ReadError;
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
pub use dalek_ff_group::{EdwardsPoint as XmrPoint, Scalar as XmrScalar};
use modular_frost::curve::PrimeField;
use monero::consensus::encode::Error as MoneroError;
use monero::consensus::{ReadExt, WriteExt};
use std::io::{self, Read, Write};

pub trait Readable: Sized {
    fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError>;
}

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

pub fn read_group_element<C: Ciphersuite, R: Read + ?Sized>(reader: &mut R) -> Result<C::G, MoneroError> {
    let len = reader.read_u64()? as usize;
    let mut buf = <<C as Ciphersuite>::G as GroupEncoding>::Repr::default();
    if buf.as_ref().len() < len {
        return Err(MoneroError::ParseFailed("Insufficient data left to read a group element"));
    }
    reader.read_exact(buf.as_mut())?;
    let elem = C::G::from_bytes(&buf).into_option().ok_or(MoneroError::ParseFailed("Invalid group element"))?;
    Ok(elem)
}

pub fn read_field_element<C: Ciphersuite, R: Read + ?Sized>(reader: &mut R) -> Result<C::F, MoneroError> {
    let len = reader.read_u64()? as usize;
    let mut buf = <<C as Ciphersuite>::F as PrimeField>::Repr::default();
    if buf.as_ref().len() < len {
        return Err(MoneroError::ParseFailed("Insufficient data left to read a field element"));
    }
    reader.read_exact(buf.as_mut())?;
    let elem = C::F::from_repr(buf).into_option().ok_or(MoneroError::ParseFailed("Invalid field element"))?;
    Ok(elem)
}
