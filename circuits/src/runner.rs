use crate::bytecode_verification::{ByteCodeVerification, HashByteCodeVerifier};
use blake2::Blake2b512;
use thiserror::Error;
use zkuh_rs::noir_api::{Inputs, ProgramArtifact};
use zkuh_rs::{noir_api, ultra_honk, BbApiError, CircuitComputeVkResponse, CircuitProveResponse};

/// Errors that can occur during bytecode verification.
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

/// Errors that can occur during execution and proof generation.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("No program artifact has been loaded yet. Nothing to execute.")]
    NoProgram,
    #[error("No inputs have been provided for execution.")]
    NoInputs,
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

/// Errors that can occur during proof verification.
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

/// A convenience wrapper for generating ZK-SNARK proofs for a given Noir program.
///
/// The `ProofRunner` allows you to set up a Noir program, provide inputs, verify the bytecode integrity,
/// and generate a proof. It supports customizable bytecode verification strategies through the `ByteCodeVerification` trait.
///
/// The verification key can be cached to speed up subsequent proof generations for the same program.
pub struct ProofRunner<'p, V: ByteCodeVerification = HashByteCodeVerifier<Blake2b512>> {
    /// A checksum for the bytecode being executed. It must have been generated using the algorithm as V.
    checksum: String,
    verifier: V,
    /// The compiled Noir program to execute.,
    program: Option<&'p ProgramArtifact>,
    /// The inputs to the program.
    inputs: Option<Inputs>,
    /// The verification key associated with the program. If present, substantially speeds up proof generation.
    verification_key: Option<CircuitComputeVkResponse>,
}

impl<'p, V: ByteCodeVerification> ProofRunner<'p, V> {
    /// Creates a new ProofRunner with the given bytecode checksum. Before proving, the program must be set using
    /// [`ProofRunner::set_program`].
    ///
    /// One may verify the bytecode using [`ProofRunner::verify_bytecode`] before proving.
    pub fn new<S: Into<String>>(checksum: S) -> Self {
        Self { checksum: checksum.into(), verifier: V::default(), program: None, inputs: None, verification_key: None }
    }

    /// Sets the program artifact to be used for proving.
    ///
    /// The program reference must outlive the ProofRunner.
    pub fn set_program(&mut self, program: &'p ProgramArtifact) -> &mut Self {
        self.program = Some(program);
        self
    }

    /// Provers may optionally set a verification key to speed up proof generation.
    ///
    /// This is useful when the same proof type is being executed multiple times with different inputs.
    pub fn set_verification_key(&mut self, vk: CircuitComputeVkResponse) -> &mut Self {
        self.verification_key = Some(vk);
        self
    }

    /// The verification key for the program, if available.
    ///
    /// This may be `None` if no key has been set or generated yet. When present, you can save yourself calculating
    /// the key for the equivalent [`VerificationRunner`] instance.
    pub fn verification_key(&self) -> Option<&CircuitComputeVkResponse> {
        self.verification_key.as_ref()
    }

    /// Verifies that the loaded program's bytecode matches the expected checksum.
    ///
    /// By default, the `HashByteCodeVerifier<Blake512>` is used to perform the verification.
    pub fn verify_bytecode(&self) -> Result<(), BytecodeError> {
        let program = self.program.ok_or_else(|| BytecodeError::NoProgram)?;
        verify_bytecode(program, &self.checksum, &self.verifier)
    }

    /// Sets the input values for the program.
    pub fn with_inputs(&mut self, inputs: Inputs) -> &mut Self {
        self.inputs = Some(inputs);
        self
    }

    /// Executes the loaded program with the provided inputs and generates a ZK-SNARK proof.
    ///
    /// Both `[Self::set_program]` and `[Self::with_inputs]` must have been called before invoking this method.
    /// If no verification key has been set, one will be generated and cached for future calls.
    ///
    /// Returns a `CircuitProveResponse` containing the proof and public inputs upon success.
    pub fn prove(&mut self) -> Result<CircuitProveResponse, ExecutionError> {
        let program =
            self.program.ok_or_else(|| noir_api::NoirError::Execution("No program artifact set".to_string()))?;
        if self.inputs.is_none() {
            return Err(ExecutionError::NoInputs);
        }
        let inputs = self.inputs.clone().unwrap();
        let result = noir_api::execute(program, inputs, true)?;
        let witness = noir_api::bincode_serialize(&result.witness_stack)
            .map_err(|e| ExecutionError::ser_error("Witness", e.to_string()))?;
        let bytecode = noir_api::bincode_serialize(&program.bytecode)
            .map_err(|e| ExecutionError::ser_error("ByteCode", e.to_string()))?;
        let vk = match self.verification_key {
            Some(ref vk) => vk.bytes.as_slice(),
            None => &[],
        };
        let proof = ultra_honk::prove(&bytecode, &witness, vk)?;
        if self.verification_key.is_none() {
            self.verification_key = Some(proof.vk.clone());
        }
        Ok(proof)
    }
}

/// A convenience wrapper for verifying ZK-SNARK proofs for a given Noir program.
///
/// The `VerificationRunner` allows you to set up a Noir program, verify the bytecode integrity,
/// and verify proofs. It supports customizable bytecode verification strategies through the `ByteCodeVerification` trait.
///
/// The verification key can be cached to speed up subsequent proof verifications for the same program. It is
/// *critical* that the verifier calculates the verification key _himself_ from the expected bytecode to avoid accepting
/// old or invalid proofs.
///
/// This is done by default in [`VerificationRunner::verify_proof`] if the key is not already cached.
pub struct VerificationRunner<'p, V: ByteCodeVerification = HashByteCodeVerifier<Blake2b512>> {
    verifier: V,
    /// A checksum for the bytecode being executed.
    checksum: String,
    /// The compiled Noir program to execute.,
    program: Option<&'p ProgramArtifact>,
    /// The verification key associated with the program. If present, substantially speeds up proof verification.
    verification_key: Option<CircuitComputeVkResponse>,
}

impl<'p, V: ByteCodeVerification> VerificationRunner<'p, V> {
    /// Creates a new VerificationRunner with the given bytecode checksum. Before executing any proof validation, the
    /// program must be set using [`VerificationRunner::set_program`].
    pub fn new<S: Into<String>>(checksum: S) -> Self {
        Self { checksum: checksum.into(), verifier: V::default(), program: None, verification_key: None }
    }

    /// Sets the program artifact to be used for verification.
    pub fn set_program(&mut self, program: &'p ProgramArtifact) {
        self.program = Some(program);
        self.verification_key = None;
    }

    /// Provers may optionally set a verification key to speed up proof verification.
    ///
    /// This is useful when the same proof type is being verified multiple times. However, it is *critical* that the
    /// verifier calculates the verification key _himself_ from the expected bytecode to avoid accepting invalid proofs.
    ///
    /// **Never** accept a verification key from an untrusted source.
    ///
    /// In general, it is safe to never call this method, as the key will be calculated from the bytecode when needed.
    ///
    /// However, if you have a trusted source for the verification key (e.g., you're calculating it anyway in your
    /// [`ProofRunner`]) for the same bytecode, you can save some cycles by providing it here.
    pub fn set_verification_key(&mut self, vk: CircuitComputeVkResponse) -> &mut Self {
        self.verification_key = Some(vk);
        self
    }

    /// Verifies that the loaded program's bytecode matches the expected checksum.
    ///
    /// It is recommended to call this method before verifying any proofs.
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
        let inputs = Inputs::new()
            .try_add_field("a", "456")
            .expect("to add private input a")
            .try_add_field("b", "654")
            .expect("to add input b")
            .try_add_field("product", "500000")
            .expect("to add product");
        runner.set_program(&artifact).with_inputs(inputs);
        match runner.prove() {
            Ok(_) => panic!("Proof generation should have failed"),
            Err(ExecutionError::ExecutionError(e)) => assert_eq!(e.to_string(), "Execution of contract failed: Witness execution failed: Failed to solve program: 'Cannot satisfy constraint'"),
            Err(e) => panic!("Unexpected error: {e}"),
        }
    }

    #[test]
    fn generate_valid_proof() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("demo");
        let inputs = Inputs::new()
            .try_add_field("a", "456")
            .expect("to add private input a")
            .try_add_field("b", "654")
            .expect("to add input b")
            .try_add_field("product", "298224")
            .expect("to add product");
        runner.set_program(&artifact).with_inputs(inputs);
        let verified = runner.verify_bytecode();
        assert!(verified.is_ok(), "{verified:?}");
        let proof = runner.prove().expect("proof generation should have succeeded");
        // Verifying.
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
        let inputs = Inputs::new()
            .try_add_field("a", "10000")
            .expect("to add private input a")
            .try_add_field("b", "20000")
            .expect("to add input b")
            .try_add_field("product", "298224")
            .expect("to add product");
        runner.set_program(&artifact).with_inputs(inputs);
        let verified = runner.verify_bytecode();
        assert!(verified.is_err());

        // Clearly a*b != product, but we still get a proof.
        let proof = runner.prove().expect("proof generation should have succeeded");
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

    #[test]
    fn consecutive_proofs() {
        let checksum =
            "b1d36d379f6ad2986b900d9f5ca859bec8e24ad29f9dde0bebb6521a6df9b054da9ab9a883196017d8ab5d0e35ab6c6493ea1d79c9a425f2dc9330750dbb31b0";
        let mut runner: ProofRunner = ProofRunner::new(checksum);
        let artifact = load_program("demo");
        let inputs = Inputs::new()
            .try_add_field("a", "456")
            .expect("to add private input a")
            .try_add_field("b", "654")
            .expect("to add private input b")
            .try_add_field("product", "298224")
            .expect("to add product");
        runner.set_program(&artifact).with_inputs(inputs);
        let proof = runner.prove().expect("Proof 1 generation should have succeeded");
        // Verifying.
        let mut verifier: VerificationRunner = VerificationRunner::new(checksum);
        verifier.set_program(&artifact);
        assert!(verifier.verify_proof(&proof).is_ok(), "Proof 1 verification failed");
        // Proof 2
        let inputs = Inputs::new()
            .try_add_field("a", "912")
            .expect("to add private input a")
            .try_add_field("b", "327")
            .expect("to add private input b")
            .try_add_field("product", "298224")
            .expect("to add product");
        runner.with_inputs(inputs);
        let proof = runner.prove().expect("Proof 2 generation should have succeeded");
        assert!(verifier.verify_proof(&proof).is_ok(), "Proof 2 verification failed");
    }
}
