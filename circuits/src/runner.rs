use crate::bytecode_verification::{ByteCodeVerification, HashByteCodeVerifier};
use blake2::Blake2b512;
use thiserror::Error;
use zkuh_rs::noir_api::{ExecutionResult, Inputs, Program, ProgramArtifact};
use zkuh_rs::{noir_api, ultra_honk, BbApiError, CircuitComputeVkResponse, CircuitProveResponse};

#[derive(Debug, Error)]
pub enum BytecodeError {
    #[error("The Bytecode does not match expected checksum")]
    BytecodeMismatch,
    #[error("No program artifact has been loaded yet. Nothing to verify against.")]
    NoProgram,
    #[error("Serialization error: {0}")]
    SerializationError(#[from] std::io::Error),
    #[error("Invalid checksum format. It should be a hex string: {0}")]
    InvalidChecksum(String),
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("No program artifact has been loaded yet. Nothing to execute.")]
    NoProgram,
    #[error("Execution error: {0}")]
    ExecutionError(#[from] noir_api::NoirError),
    #[error("Error serializing {src}: {reason}")]
    SerializeError { src: String, reason: String },
    #[error("Prover error: {0}")]
    ProverError(#[from] BbApiError),
}

impl ExecutionError {
    pub fn ser_error<S: Into<String>, R: Into<String>>(src: S, reason: R) -> Self {
        ExecutionError::SerializeError { src: src.into(), reason: reason.into() }
    }
}

#[derive(Debug, Error)]
pub enum ProofVerificationError {
    #[error("No program artifact has been loaded yet. Nothing to execute.")]
    NoProgram,
    #[error("Error serializing {src}: {reason}")]
    SerializeError { src: String, reason: String },
    #[error("Verification error: {0}")]
    VerificationError(#[from] BbApiError),
    #[error("The proof is invalid.")]
    InvalidProof,
}

impl ProofVerificationError {
    pub fn ser_error<S: Into<String>, R: Into<String>>(src: S, reason: R) -> Self {
        ProofVerificationError::SerializeError { src: src.into(), reason: reason.into() }
    }
}

pub struct ProofRunner<'p, V: ByteCodeVerification = HashByteCodeVerifier<Blake2b512>> {
    /// A checksum for the bytecode being executed. It must have been generated using the same digest algorithm as D.
    checksum: String,
    verifier: V,
    /// The complied Noir program to execute.,
    program: Option<&'p ProgramArtifact>,
    /// The inputs to the program.
    inputs: Inputs,
    /// The result of the last execution.
    execution_result: Option<ExecutionResult>,
    /// The verification key associated with the program. If present, substantially speeds up proof generation.
    verification_key: Option<CircuitComputeVkResponse>,
    proof: Option<CircuitProveResponse>,
}

impl<'p, V: ByteCodeVerification> ProofRunner<'p, V> {
    pub fn new<S: Into<String>>(checksum: S) -> Self {
        Self {
            checksum: checksum.into(),
            verifier: V::default(),
            program: None,
            inputs: Inputs::new(),
            execution_result: None,
            verification_key: None,
            proof: None,
        }
    }

    pub fn set_program(&mut self, program: &'p ProgramArtifact) -> &mut Self {
        self.program = Some(program);
        self
    }

    pub fn set_verification_key(&mut self, vk: CircuitComputeVkResponse) -> &mut Self {
        self.verification_key = Some(vk);
        self
    }

    pub fn verification_key(&self) -> Option<&CircuitComputeVkResponse> {
        self.verification_key.as_ref()
    }

    pub fn proof(&self) -> Option<CircuitProveResponse> {
        self.proof.clone()
    }

    pub fn verify_bytecode(&self) -> Result<(), BytecodeError> {
        let program = self.program.ok_or_else(|| BytecodeError::NoProgram)?;
        verify_bytecode(program, &self.checksum, &self.verifier)
    }

    /// Updates the input values for the program.
    ///
    /// `with_inputs` takes a closure that receives the current `Inputs` and returns a modified `Inputs`.
    /// Inputs are added in the closure, so calling it more than once will accumulate inputs.
    pub fn with_inputs<F>(&mut self, updater: F)
    where
        F: FnOnce(Inputs) -> Inputs,
    {
        let mut temp = Inputs::new();
        // We swap out the existing input here so that `with_inputs` can be called multiple times.
        std::mem::swap(&mut self.inputs, &mut temp);
        // temp holds the original; self.inputs holds empty Inputs.
        self.inputs = updater(temp);
    }

    pub fn prove(&mut self) -> Result<(), ExecutionError> {
        self.proof = None;
        let program =
            self.program.ok_or_else(|| noir_api::NoirError::Execution("No program artifact set".to_string()))?;
        let result = noir_api::execute(program, self.inputs.clone(), true)?;
        let witness = noir_api::bincode_serialize(&result.witness_stack)
            .map_err(|e| ExecutionError::ser_error("Witness", e.to_string()))?;
        let bytecode = noir_api::bincode_serialize(&program.bytecode)
            .map_err(|e| ExecutionError::ser_error("ByteCode", e.to_string()))?;
        self.execution_result = Some(result);
        let vk = match self.verification_key {
            Some(ref vk) => vk.bytes.as_slice(),
            None => &[],
        };
        let proof = ultra_honk::prove(&bytecode, &witness, vk)?;
        if self.verification_key.is_none() {
            self.verification_key = Some(proof.vk.clone());
        }
        self.proof = Some(proof);
        Ok(())
    }

    pub fn execution_result(&self) -> Option<&ExecutionResult> {
        self.execution_result.as_ref()
    }
}

pub struct VerificationRunner<'p, V: ByteCodeVerification = HashByteCodeVerifier<Blake2b512>> {
    verifier: V,
    /// A checksum for the bytecode being executed.
    checksum: String,
    /// The complied Noir program to execute.,
    program: Option<&'p ProgramArtifact>,
    /// The verification key associated with the program. If present, substantially speeds up proof generation.
    verification_key: Option<CircuitComputeVkResponse>,
}

impl<'p, V: ByteCodeVerification> VerificationRunner<'p, V> {
    pub fn new<S: Into<String>>(checksum: S) -> Self {
        Self { checksum: checksum.into(), verifier: V::default(), program: None, verification_key: None }
    }

    pub fn set_program(&mut self, program: &'p ProgramArtifact) {
        self.program = Some(program);
        self.verification_key = None;
    }

    pub fn verify_bytecode(&self) -> Result<(), BytecodeError> {
        let program = self.program.ok_or_else(|| BytecodeError::NoProgram)?;
        verify_bytecode(program, &self.checksum, &self.verifier)
    }

    /// Verifies the provided proof against the loaded program.
    ///
    /// Verification consists of two steps:
    /// 1. If not present, the verification key is recalculated from the loaded program's bytecode.
    ///    This is only done once, and cached for future calls.
    /// 2. The proof is verified using the verification key. The vk given in the proof itself is ignored.
    pub fn verify_proof(&mut self, proof: &CircuitProveResponse) -> Result<(), ProofVerificationError> {
        let program = self.program.ok_or(ProofVerificationError::NoProgram)?;
        // We recalculate the verification key to convince ourselves that the peer hasn't handed us any old proof. We
        // need a proof for the exact bytecode we expect.
        if self.verification_key.is_none() {
            let bytecode = noir_api::bincode_serialize(&program.bytecode)
                .map_err(|e| ProofVerificationError::ser_error("ByteCode", e.to_string()))?;
            let vk = ultra_honk::get_vk(&bytecode)?;
            self.verification_key = Some(vk);
        }

        let vk = self.verification_key.clone().unwrap();

        let proof = CircuitProveResponse { public_inputs: proof.public_inputs.clone(), proof: proof.proof.clone(), vk };
        match ultra_honk::verify(proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ProofVerificationError::InvalidProof),
            Err(e) => Err(ProofVerificationError::VerificationError(e)),
        }
    }
}

fn verify_bytecode(
    program: &ProgramArtifact,
    checksum: &str,
    verifier: &impl ByteCodeVerification,
) -> Result<(), BytecodeError> {
    let bytecode = noir_api::bincode_serialize(&program.bytecode)?;
    let bin_checksum = hex::decode(checksum).map_err(|e| BytecodeError::InvalidChecksum(e.to_string()))?;
    match verifier.verify_bytecode(&bytecode, &bin_checksum) {
        true => Ok(()),
        false => Err(BytecodeError::BytecodeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode_verification::DummyByteCodeVerifier;

    fn load_program(name: &str) -> ProgramArtifact {
        let path = format!("test_vectors/{}.json", name);
        noir_api::artifacts::load_artifact(path).expect("Failed to load program artifact")
    }

    #[test]
    fn invalid_checksum() {
        let mut runner: ProofRunner = ProofRunner::new("deadbeef");
        let artifact = load_program("init");
        runner.set_program(&artifact);
        let result = runner.verify_bytecode();
        assert!(matches!(result, Err(BytecodeError::BytecodeMismatch)));
    }

    #[test]
    fn checksum_with_dummy_validator() {
        let mut runner = ProofRunner::<DummyByteCodeVerifier>::new("deadbeef");
        let artifact = load_program("init");
        runner.set_program(&artifact);
        assert!(runner.verify_bytecode().is_ok());
    }

    #[test]
    fn valid_checksum() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("demo");
        runner.set_program(&artifact);
        // let actual = runner.verifier.calculate_checksum(&noir_api::bincode_serialize(&artifact.bytecode).unwrap());
        // println!("Calculated checksum: {}", hex::encode(&actual));
        let verified = runner.verify_bytecode();
        assert!(verified.is_ok(), "{verified:?}");
    }

    #[test]
    fn validate_without_program() {
        let runner: ProofRunner = ProofRunner::new("a0f3d6a2c4cb28b0");
        assert!(matches!(runner.verify_bytecode(), Err(BytecodeError::NoProgram)));
    }

    #[test]
    fn cannot_generate_invalid_proof() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("demo");
        runner.set_program(&artifact);
        runner.with_inputs(|inputs| {
            inputs
                .try_add_field("a", "456")
                .expect("to add private input a")
                .try_add_field("b", "654")
                .expect("to add input blinding_DLEQ")
                .try_add_field("product", "500000")
                .expect("to add product")
        });
        match runner.prove() {
            Ok(_) => panic!("Proof generation should have failed"),
            Err(ExecutionError::ExecutionError(e)) => assert_eq!(e.to_string(), "Execution of contract failed: Witness execution failed: Failed to solve program: 'Cannot satisfy constraint'"),
            Err(e) => panic!("Unexpected error: {e}"),
        }
        assert!(runner.proof.is_none())
    }

    #[test]
    fn generate_valid_proof() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("demo");
        runner.set_program(&artifact);
        let verified = runner.verify_bytecode();
        assert!(verified.is_ok(), "{verified:?}");
        runner.with_inputs(|inputs| {
            inputs
                .try_add_field("a", "456")
                .expect("to add private input a")
                .try_add_field("b", "654")
                .expect("to add input blinding_DLEQ")
                .try_add_field("product", "298224")
                .expect("to add product")
        });
        assert!(runner.prove().is_ok(), "Proof generation failed");
        let proof = runner.proof().unwrap();
        // Proving.
        let mut verifier: VerificationRunner = VerificationRunner::new(checksum);
        verifier.set_program(&artifact);
        assert!(verifier.verify_bytecode().is_ok(), "Bytecode verification failed");
        assert!(verifier.verify_proof(&proof).is_ok(), "Proof verification failed");
    }

    /// In this test, the prover generates a valid proof, but for a completely different circuit. It has the same
    /// parameters, so it tries to pass it off as a valid proof for the expected circuit. The verifier should catch
    /// this.
    #[test]
    fn defeat_evil_proof() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("evil_demo");
        runner.set_program(&artifact);
        let verified = runner.verify_bytecode();
        assert!(verified.is_err());
        runner.with_inputs(|inputs| {
            inputs
                .try_add_field("a", "10000")
                .expect("to add private input a")
                .try_add_field("b", "20000")
                .expect("to add input blinding_DLEQ")
                .try_add_field("product", "298224")
                .expect("to add product")
        });
        // Clearly a*b != product, but we still get a proof.
        assert!(runner.prove().is_ok(), "Proof generation failed");
        let proof = runner.proof().unwrap();
        // A naive verifier can be fooled.
        let mut verifier: VerificationRunner = VerificationRunner::new(checksum);
        verifier.set_program(&artifact);
        assert!(verifier.verify_proof(&proof).is_ok(), "Naiive verification failed");

        // Proper checking catches the evil proof.
        let mut verifier: VerificationRunner = VerificationRunner::new(checksum);
        // Point to the correct bytecode!
        let artifact = load_program("demo");
        verifier.set_program(&artifact);
        assert!(verifier.verify_bytecode().is_ok(), "Bytecode verification failed");
        match verifier.verify_proof(&proof) {
            Ok(_) => panic!("Proof verification should have failed"),
            Err(ProofVerificationError::InvalidProof) => { /* success */ }
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }
}
