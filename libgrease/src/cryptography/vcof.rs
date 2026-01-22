use crate::cryptography::witness::{AsXmrPoint, Offset};
use crate::grease_protocol::utils::Readable;
use modular_frost::sign::Writable;
use thiserror::Error;
use zeroize::Zeroize;

pub trait VcofPrivateData: Zeroize {
    type W: Offset;
    fn from_parts(prev: Self::W, next: Self::W) -> Self;
    fn prev(&self) -> &Self::W;
    fn next(&self) -> &Self::W;
}

pub trait VcofPublicData {
    type G: AsXmrPoint;
    fn from_parts(prev: Self::G, next: Self::G) -> Self;
    fn prev(&self) -> &Self::G;
    fn next(&self) -> &Self::G;
}

pub trait VerifiableConsecutiveOnewayFunction {
    type Witness: Offset;
    type PrivateData: VcofPrivateData<W = Self::Witness>;
    type PublicData: VcofPublicData<G = <Self::Witness as Offset>::Public>;
    type Proof: Writable + Readable;
    type Context;

    /// Given an input item, compute the next item in the sequence.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn compute_next(
        &self,
        update_count: u64,
        prev: &Self::Witness,
        ctx: &Self::Context,
    ) -> Result<Self::Witness, ProvingError>;

    /// Create a proof that `next` is the valid consecutive output of applying the VCOF to `input`.
    ///
    /// Don't call this method directly; use `next` instead to get both the next item and its proof.
    fn create_proof(
        &self,
        index: u64,
        private_input: &Self::PrivateData,
        public_input: &Self::PublicData,
        ctx: &Self::Context,
    ) -> Result<Self::Proof, ProvingError>;

    /// Calculate the next item in the VCOF sequence along with a proof of correctness.
    ///
    /// If the proof and next value are computed atomically, you can override the default implementation, and make
    /// [`compute_next`] and [`create_proof`] no-ops.
    /// Otherwise, you need to implement [`compute_next`] and [`create_proof`] accordingly.
    fn next(
        &self,
        index: u64,
        prev_witness: &Self::Witness,
        ctx: &Self::Context,
    ) -> Result<(Self::Proof, Self::PublicData), ProvingError> {
        if index == 0 {
            let err = ProvingError::DerivationError("update_count must be at least 1".to_string());
            return Err(err);
        }
        let next_witness = self.compute_next(index, prev_witness, ctx)?;
        let next_public = next_witness.as_public();
        let mut private_input = <Self::PrivateData as VcofPrivateData>::from_parts(prev_witness.clone(), next_witness);
        let prev_public = prev_witness.as_public();
        let public_input = <Self::PublicData as VcofPublicData>::from_parts(prev_public, next_public);
        let proof = self.create_proof(index, &private_input, &public_input, ctx).map_err(|e| e.into())?;
        private_input.zeroize();
        Ok((proof, public_input))
    }

    /// Verify that `next` is the valid consecutive output of applying the VCOF to `prev`.
    fn verify(
        &self,
        update_count: u64,
        public_input: &Self::PublicData,
        proof: &Self::Proof,
        ctx: &Self::Context,
    ) -> Result<(), InvalidProof>;
}

pub trait NextWitness: Default {
    type W: Offset;
    type Err: std::error::Error;
    fn next_witness(&self, update_count: u64, prev: &Self::W) -> Result<Self::W, Self::Err>;
}

#[derive(Debug, Clone, Error)]
pub enum ProvingError {
    #[error("Error during VCOF proof generation: {0}")]
    ProvingError(String),
    #[error("Could not derive the next item in the VCOF sequence: {0}")]
    DerivationError(String),
    #[error("Error during VCOF initialization: {0}")]
    InitializationError(String),
}

impl ProvingError {
    pub fn derive_err(msg: impl Into<String>) -> Self {
        ProvingError::DerivationError(msg.into())
    }

    pub fn prove_err(msg: impl Into<String>) -> Self {
        ProvingError::ProvingError(msg.into())
    }

    pub fn init_err(msg: impl Into<String>) -> Self {
        ProvingError::InitializationError(msg.into())
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[error("Invalid proof for update count {update_count}")]
pub struct InvalidProof {
    update_count: u64,
}

impl InvalidProof {
    pub fn new(update_count: u64) -> Self {
        Self { update_count }
    }
}

impl From<u64> for InvalidProof {
    fn from(update_count: u64) -> Self {
        Self::new(update_count)
    }
}
