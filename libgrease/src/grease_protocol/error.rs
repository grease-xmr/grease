use thiserror::Error;

#[derive(Debug, Error)]
pub enum DleqError {
    #[error("The provided scalar cannot be represented as a scalar on the Ed25519 curve.")]
    InvalidEd25519Scalar,
    #[error("The provided scalar cannot be represented as a field element on the Foreign curve.")]
    InvalidForeignFieldElement,
    #[error("The ED25519 scalar cannot be represented on the Foreign curve.")]
    Ed25519ScalarTooLarge,
    #[error("An equivalent Foreign and Ed25519 representation could not be found during initial witness generation.")]
    InitializationFailure,
    #[error("DLEQ proof verification failed.")]
    VerificationFailure,
    #[error("I/O error occurred during reading data.")]
    ReadError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum WitnessProofCommitmentError {
    #[error("The provided commitment does not match the expected value.")]
    CommitmentMismatch,
    #[error("Failed to serialize or deserialize commitment data.")]
    SerializationError,
    #[error("An error occurred during commitment initialization.")]
    InitializationFailure,
}

#[derive(Debug, Error)]
pub enum WitnessProofError {
    #[error("The provided proof is invalid.")]
    InvalidProof,
    #[error("Failed to serialize or deserialize proof data.")]
    SerializationError,
    #[error("An error occurred during proof generation. {0}")]
    ProofGenerationFailure(String),
}

#[derive(Debug, Error)]
pub enum GreaseProtocolError {}
