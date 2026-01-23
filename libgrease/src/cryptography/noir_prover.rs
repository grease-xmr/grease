//! This module wraps ProofRunner and VCOF-specific data structures into a simple struct that can be passed to
//! [`crate::vcof_snark_dleq::SnarkDleqVcofProver`].

use crate::cryptography::vcof::{VcofPrivateData, VcofPublicData};
use log::error;
use thiserror::Error;
use zkuh_rs::noir_api::{InputError, Inputs, ProgramArtifact};
use zkuh_rs::runner::{BytecodeError, ExecutionError, ProofRunner};
use zkuh_rs::uint256_to_bytes;

pub trait InputConverter {
    type Private: VcofPrivateData;
    type Public: VcofPublicData;

    fn to_inputs(&self, index: u64, private: &Self::Private, public: &Self::Public) -> Result<Inputs, InputError>;
}

pub struct NoirProver<'p, C: InputConverter> {
    artifact: &'p ProgramArtifact,
    runner: ProofRunner<'p>,
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
        Ok(Self { artifact, runner, input_converter })
    }

    pub fn prove(&self, i: u64, private_in: &C::Private, public_in: &C::Public) -> Result<Vec<u8>, NoirProverError> {
        let mut runner = self.runner.clone();
        let inputs = self.input_converter.to_inputs(i, private_in, public_in)?;
        runner.with_inputs(inputs);
        let result = runner.prove()?;
        // For VCOF proofs, we expect no return value from the program
        debug_assert!(result.return_value().is_none());
        let proof = uint256_to_bytes(result.proof());
        Ok(proof)
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
}
