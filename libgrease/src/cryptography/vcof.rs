use crate::grease_protocol::utils::Readable;
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait VerifiableConsecutiveOnewayFunction<SF>
where
    SF: Ciphersuite,
{
    type Proof: Writable + Readable + VcofProof<SF>;

    /// Given an input item, compute the next item in the sequence.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn compute_next(&self, input: &VcofRecord<SF, Self::Proof>) -> Result<SF::F, VcofError>;

    /// Create a proof that `next` is the valid consecutive output of applying the VCOF to `input`.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn create_proof(&self, input: &VcofRecord<SF, Self::Proof>) -> Result<Self::Proof, VcofError>;

    /// Calculate the next item in the VCOF sequence along with a proof of correctness.
    ///
    /// If the proof and next value are computed atomically, you can override the default implementation, and make
    /// [`compute_next`] and [`create_proof`] no-ops.
    /// Otherwise, you need to implement [`compute_next`] and [`create_proof`] accordingly.
    fn next(&self, input: &VcofRecord<SF, Self::Proof>) -> Result<VcofRecord<SF, Self::Proof>, VcofError> {
        let next = Zeroizing::new(self.compute_next(input)?);
        let next_pub = SF::generator() * *next;
        let proof = self.create_proof(input)?;
        Ok(VcofRecord {
            index: input.index + 1,
            current: input.next.clone(),
            current_pub: input.next_pub,
            next,
            next_pub,
            proof,
        })
    }
}

pub trait VcofProof<SF>
where
    SF: Ciphersuite,
{
    /// Verify that `next` is the valid consecutive output of applying the VCOF to `input` using this proof.
    fn verify(&self, input: &SF::G, next: &SF::G) -> Result<(), VcofError>;
}

#[derive(Debug, Clone, Error)]
pub enum VcofError {
    #[error("The proof provided is invalid.")]
    InvalidProof,
    #[error("Error during VCOF proof generation: {0}")]
    ProvingError(String),
    #[error("Could not derive the next item in the VCOF sequence: {0}")]
    DerivationError(String),
}

/// The output of a Verifiable Consecutive Oneway Function (VCOF) at a given index, along with a proof of correctness.
pub struct VcofRecord<SF, P>
where
    SF: Ciphersuite,
    P: VcofProof<SF> + Writable + Readable + Sized,
{
    /// The index of this record in the VCOF sequence.
    index: u64,
    /// The i-th secret value in the sequence.
    current: Zeroizing<SF::F>,
    /// The public key corresponding to the current secret value.
    current_pub: SF::G,
    /// The (i+1)-th secret value in the sequence.
    next: Zeroizing<SF::F>,
    /// The public key corresponding to the next secret value.
    next_pub: SF::G,
    /// The proof that `next` is the valid consecutive output of applying the VCOF to `current`.
    proof: P,
}

impl<SF, P> VcofRecord<SF, P>
where
    SF: Ciphersuite,
    P: VcofProof<SF> + Writable + Readable + Sized,
{
    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn current(&self) -> &Zeroizing<SF::F> {
        &self.current
    }

    pub fn current_pub(&self) -> &SF::G {
        &self.current_pub
    }

    pub fn next(&self) -> &Zeroizing<SF::F> {
        &self.next
    }

    pub fn next_pub(&self) -> &SF::G {
        &self.next_pub
    }

    pub fn proof(&self) -> &P {
        &self.proof
    }
}
