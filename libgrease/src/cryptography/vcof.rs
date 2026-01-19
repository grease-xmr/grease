use crate::grease_protocol::utils::Readable;
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait VerifiableConsecutiveOnewayFunction<SF>
where
    SF: Ciphersuite,
{
    type Proof: Writable + Readable;
    type Context;

    /// Given an input item, compute the next item in the sequence.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn compute_next(
        &self,
        update_count: u64,
        prev: &SF::F,
        pub_prev: &SF::G,
        ctx: &Self::Context,
    ) -> Result<SF::F, VcofError>;

    /// Create a proof that `next` is the valid consecutive output of applying the VCOF to `input`.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn create_proof(&self, input: &VcofProofInput<SF>, ctx: &Self::Context) -> Result<Self::Proof, VcofError>;

    /// Calculate the next item in the VCOF sequence along with a proof of correctness.
    ///
    /// If the proof and next value are computed atomically, you can override the default implementation, and make
    /// [`compute_next`] and [`create_proof`] no-ops.
    /// Otherwise, you need to implement [`compute_next`] and [`create_proof`] accordingly.
    fn next(
        &self,
        update_count: u64,
        prev: &SF::F,
        prev_pub: &SF::G,
        ctx: &Self::Context,
    ) -> Result<VcofProofResult<SF, Self::Proof>, VcofError> {
        let next = Zeroizing::new(self.compute_next(update_count, prev, prev_pub, ctx)?);
        let next_pub = SF::generator() * *next;
        let input = VcofProofInput {
            index: update_count,
            prev: Zeroizing::new(prev.clone()),
            prev_pub: prev_pub.clone(),
            next,
            next_pub,
        };
        let proof = self.create_proof(&input, ctx)?;
        let result = VcofProofResult::new(input, proof);
        Ok(result)
    }

    /// Verify that `next` is the valid consecutive output of applying the VCOF to `input` using this proof.
    fn verify(
        &self,
        update_count: u64,
        prev: &SF::G,
        next: &SF::G,
        proof: &Self::Proof,
        ctx: &Self::Context,
    ) -> Result<(), VcofError>;
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
pub struct VcofProofInput<SF>
where
    SF: Ciphersuite,
{
    /// The index of the next record in the VCOF sequence.
    pub index: u64,
    /// The i-th secret value in the sequence.
    pub prev: Zeroizing<SF::F>,
    /// The public key corresponding to the current secret value.
    pub prev_pub: SF::G,
    /// The (i+1)-th secret value in the sequence.
    pub next: Zeroizing<SF::F>,
    /// The public key corresponding to the next secret value.
    pub next_pub: SF::G,
}

pub struct VcofProofResult<SF, P>
where
    SF: Ciphersuite,
    P: Writable + Readable + Sized,
{
    pub input: VcofProofInput<SF>,
    pub proof: P,
}

impl<SF, P> VcofProofResult<SF, P>
where
    SF: Ciphersuite,
    P: Writable + Readable + Sized,
{
    /// Create a new `VcofProofResult` with the given values.
    pub fn new(input: VcofProofInput<SF>, proof: P) -> Self {
        Self { input, proof }
    }
}
