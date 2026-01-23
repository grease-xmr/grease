//! This module wraps ProofRunner and VCOF-specific data structures into a simple struct that can be passed to
//! [`crate::vcof_snark_dleq::SnarkDleqVcofProver`].

use crate::cryptography::vcof::{VcofPrivateData, VcofPublicData};
use log::error;
use thiserror::Error;
use zkuh_rs::noir_api::{InputError, Inputs, ProgramArtifact};
use zkuh_rs::runner::{BytecodeError, ExecutionError, ProofRunner, VerificationRunner};
use zkuh_rs::{bytes_to_uint256, uint256_to_bytes};

pub trait InputConverter {
    type Private: VcofPrivateData;
    type Public: VcofPublicData;

    fn to_inputs(
        &self,
        index: u64,
        private: Option<&Self::Private>,
        public: &Self::Public,
    ) -> Result<Inputs, InputError>;
}

pub struct NoirProver<'p, C: InputConverter> {
    artifact: &'p ProgramArtifact,
    runner: ProofRunner<'p>,
    verifier: VerificationRunner<'p>,
    input_converter: &'p C,
}

impl<'p, C: InputConverter> NoirProver<'p, C> {
    pub fn new(
        checksum: impl Into<String>,
        artifact: &'p ProgramArtifact,
        input_converter: &'p C,
    ) -> Result<Self, NoirProverError> {
        let checksum = checksum.into();
        let mut runner = ProofRunner::new(&checksum);
        runner.set_program(artifact);
        if let Err(err) = runner.verify_bytecode() {
            let actual = runner.bytecode_checksum().unwrap_or("<unknown>".to_string());
            error!(
                "🚨🚨🚨 The Update circuit bytecode checksum test failed! 🚨🚨🚨\n\
            This could be a bug, or someone is doing something fishy. Make sure that Grease is up-to-date and try run\
            it again. If the problem persists, please open an issue on GitHub.\n\
            Expected checksum: {checksum}, Actual checksum: {actual}\n\
            Error details: {}",
                err
            );
            return Err(err.into());
        }
        let mut verifier = VerificationRunner::new(&checksum);
        verifier.set_program(artifact);
        Ok(Self { artifact, runner, verifier, input_converter })
    }

    pub fn prove(&self, i: u64, private_in: &C::Private, public_in: &C::Public) -> Result<Vec<u8>, NoirProverError> {
        let mut runner = self.runner.clone();
        let inputs = self.input_converter.to_inputs(i, Some(private_in), public_in)?;
        runner.with_inputs(inputs);
        let result = runner.prove()?;
        // For VCOF proofs, we expect no return value from the program
        debug_assert!(result.return_value().is_none());
        let proof = uint256_to_bytes(result.proof());
        Ok(proof)
    }

    pub fn verify(&self, i: u64, public_in: &C::Public, proof: &[u8]) -> Result<(), NoirProverError> {
        let mut verifier = self.verifier.clone();
        let inputs = self.input_converter.to_inputs(i, None, public_in)?;
        let proof = bytes_to_uint256(proof)
            .map_err(|e| NoirProverError::VerifierError(format!("Corrupted or SNARK proof. {e}")))?;
        let abi = &self.artifact.abi;
        let public_inputs = inputs
            .public_inputs(abi)
            .map_err(|e| NoirProverError::VerifierError(format!("Missing or invalid public inputs. {e}")))?;
        verifier
            .verify_proof(&proof, &public_inputs)
            .map_err(|e| NoirProverError::VerifierError(format!("SNARK proof is invalid. {e}")))?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum NoirProverError {
    #[error("Bytecode error: {0}")]
    BytecodeError(#[from] BytecodeError),
    #[error("Input conversion error: {0}")]
    InputError(#[from] InputError),
    #[error("Noir Execution error: {0}")]
    ExecutionError(#[from] ExecutionError),
    #[error("Proof verification error: {0}")]
    VerifierError(String),
}
