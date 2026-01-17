use crate::grease_protocol::utils::Readable;
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait VerifiableConsecutiveOnewayFunction<C>
where
    C: Ciphersuite,
{
    type Proof: Writable + Readable + VcofProof<C>;

    /// Given an input item, compute the next item in the sequence.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn compute_next(&self, input: &VcofRecord<C, Self::Proof>) -> Result<C::F, VcofError>;

    /// Create a proof that `next` is the valid consecutive output of applying the VCOF to `input`.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn create_proof(&self, input: &VcofRecord<C, Self::Proof>) -> Result<Self::Proof, VcofError>;

    /// Calculate the next item in the VCOF sequence along with a proof of correctness.
    ///
    /// If the proof and next value are computed atomically, you can override the default implementation, and make
    /// [`compute_next`] and [`create_proof`] no-ops.
    /// Otherwise, you need to implement [`compute_next`] and [`create_proof`] accordingly.
    fn next(&self, input: &VcofRecord<C, Self::Proof>) -> Result<VcofRecord<C, Self::Proof>, VcofError> {
        let next = Zeroizing::new(self.compute_next(input)?);
        let next_pub = C::generator() * *next;
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

pub trait VcofProof<C>
where
    C: Ciphersuite,
{
    /// Verify that `next` is the valid consecutive output of applying the VCOF to `input` using this proof.
    fn verify(&self, input: &C::G, next: &C::G) -> Result<(), VcofError>;
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
pub struct VcofRecord<C, P>
where
    C: Ciphersuite,
    P: VcofProof<C> + Writable + Readable + Sized,
{
    /// The index of this record in the VCOF sequence.
    index: u64,
    /// The i-th secret value in the sequence.
    current: Zeroizing<C::F>,
    /// The public key corresponding to the current secret value.
    current_pub: C::G,
    /// The (i+1)-th secret value in the sequence.
    next: Zeroizing<C::F>,
    /// The public key corresponding to the next secret value.
    next_pub: C::G,
    /// The proof that `next` is the valid consecutive output of applying the VCOF to `current`.
    proof: P,
}

impl<C, P> VcofRecord<C, P>
where
    C: Ciphersuite,
    P: VcofProof<C> + Writable + Readable + Sized,
{
    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn current(&self) -> &Zeroizing<C::F> {
        &self.current
    }

    pub fn current_pub(&self) -> &C::G {
        &self.current_pub
    }

    pub fn next(&self) -> &Zeroizing<C::F> {
        &self.next
    }

    pub fn next_pub(&self) -> &C::G {
        &self.next_pub
    }

    pub fn proof(&self) -> &P {
        &self.proof
    }
}
