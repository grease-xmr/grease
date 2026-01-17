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
pub struct SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    dleq: <Ed25519 as Dleq<SF>>::Proof,
    snark: Vec<u8>,
}

impl<SF> VcofProof<SF> for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn verify(&self, input: &SF::G, next: &SF::G) -> Result<(), VcofError> {
        // Verify the DLEQ proof first
        error!("DLEQ proof verification not implemented.");

        // Verify the SNARK proof (not implemented here)
        // You would typically call into your SNARK verification library here
        error!("SNARK proof verification not implemented.");
        Ok(())
    }
}

impl<SF> Readable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, crate::error::ReadError> {
        todo!()
    }
}

impl<SF> Writable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        todo!()
    }
}

/// A Verifiable Consecutive Oneway Function (VCOF) implementation using SNARKs the KeyUpdate function with a DLEQ
/// proof to prove equivalence between the SNARK-friendly curve (SF) and Ed25519.
pub struct VcofSnarkDleq<SF: Ciphersuite> {
    update_count: u64,
    current_secret: SF::F,
}

impl<SF> VerifiableConsecutiveOnewayFunction<SF> for VcofSnarkDleq<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    type Proof = SnarkDleqProof<SF>;

    fn compute_next(&self, input: &VcofRecord<SF, Self::Proof>) -> Result<SF::F, VcofError> {
        let i = input.index();
        todo!()
    }

    fn create_proof(&self, input: &VcofRecord<SF, Self::Proof>) -> Result<Self::Proof, VcofError> {
        todo!()
    }
}

/// Calculate the next value in the VCOF sequence using the given index and i-th secret. This update function is a
/// black-box function, meaning that it is calculated outside the context of a SNARK circuit.
///
/// `SF` should be chosen to be a SNARK-friendly ciphersuite, e.g., Poseidon2.
pub fn vcof_update<SF: Ciphersuite, D: SecureDigest>(index: u64) -> SF::F {
    todo!()
}
