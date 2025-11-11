use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use thiserror::Error;
use zeroize::Zeroizing;
use crate::grease_protocol::utils::Readable;

pub trait VerifiableConsecutiveOnewayFunction<C>
where
    C: Ciphersuite
{
    type Proof: Writable + Readable + VcofProof<C>;

    /// Given an input item, compute the next item in the sequence.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn compute_next(&self, input: &VcofOutput<C, Self::Proof>) -> Result<C::F, VcofError>;

    /// Create a proof that `next` is the valid consecutive output of applying the VCOF to `input`.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn create_proof(&self, input: &VcofOutput<C, Self::Proof>) -> Result<Self::Proof, VcofError>;

    /// Calculate the next item in the VCOF sequence along with a proof of correctness.
    ///
    /// If the proof and next value are computed atomically, you can override the default implementation, and make
    /// [`compute_next`] and [`create_proof`] no-ops.
    /// Otherwise, you need to implement [`compute_next`] and [`create_proof`] accordingly.
    fn next(&self, input: &VcofOutput<C, Self::Proof>) -> Result<VcofOutput<C, Self::Proof>,VcofError> {
        let next = Zeroizing::new(self.compute_next(input)?);
        let next_pub = C::generator() * *next;
        let proof = self.create_proof(input)?;
        Ok(VcofOutput {
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
    C: Ciphersuite
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

pub struct VcofOutput<C, P>
where
    C: Ciphersuite,
    P: VcofProof<C> + Writable + Readable + Sized,
{
    index: u64,
    current: Zeroizing<C::F>,
    current_pub: C::G,
    next: Zeroizing<C::F>,
    next_pub: C::G,
    proof: P,
}