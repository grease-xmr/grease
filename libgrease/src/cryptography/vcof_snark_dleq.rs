use crate::cryptography::dleq::Dleq;
use crate::cryptography::vcof::{VcofError, VcofProof, VcofRecord, VerifiableConsecutiveOnewayFunction};
use crate::grease_protocol::utils::Readable;
use ciphersuite::{Ciphersuite, Ed25519};
use flexible_transcript::SecureDigest;
use log::error;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use std::io::{Read, Write};

/// A VCOF proof using Snark+DLEQ consists of the ZK-SNARK, _plus_ a DLEQ proof to link the SNARK-friendly curve and Ed25519.
pub struct SnarkDleqProof<C>
where
    C: Curve,
    Ed25519: Dleq<C>,
{
    dleq: <Ed25519 as Dleq<C>>::Proof,
    snark: Vec<u8>,
}

impl<C> VcofProof<C> for SnarkDleqProof<C>
where
    C: Curve,
    Ed25519: Dleq<C>,
{
    fn verify(&self, input: &C::G, next: &C::G) -> Result<(), VcofError> {
        // Verify the DLEQ proof first
        error!("DLEQ proof verification not implemented.");

        // Verify the SNARK proof (not implemented here)
        // You would typically call into your SNARK verification library here
        error!("SNARK proof verification not implemented.");
        Ok(())
    }
}

impl<C> Readable for SnarkDleqProof<C>
where
    C: Curve,
    Ed25519: Dleq<C>,
{
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, crate::error::ReadError> {
        todo!()
    }
}

impl<C> Writable for SnarkDleqProof<C>
where
    C: Curve,
    Ed25519: Dleq<C>,
{
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        todo!()
    }
}

/// A Verifiable Consecutive Oneway Function (VCOF) implementation using SNARKs the KeyUpdate function with a DLEQ
/// proof to prove equivalence between the SNARK-friendly curve (C) and Ed25519.
pub struct VcofSnarkDleq<C: Ciphersuite> {
    update_count: u64,
    current_secret: C::F,
}

impl<C> VerifiableConsecutiveOnewayFunction<C> for VcofSnarkDleq<C>
where
    C: Curve,
    Ed25519: Dleq<C>,
{
    type Proof = SnarkDleqProof<C>;

    fn compute_next(&self, input: &VcofRecord<C, Self::Proof>) -> Result<C::F, VcofError> {
        let i = input.index();
        todo!()
    }

    fn create_proof(&self, input: &VcofRecord<C, Self::Proof>) -> Result<Self::Proof, VcofError> {
        todo!()
    }
}

/// Calculate the next value in the VCOF sequence using the given index and i-th secret. This update function is a
/// black-box function, meaning that it is calculated outside the context of a SNARK circuit.
///
/// `C` should be chosen to be a SNARK-friendly ciphersuite, e.g., Poseidon2.
pub fn vcof_update<C: Ciphersuite, D: SecureDigest>(index: u64) -> C::F {
    todo!()
}
