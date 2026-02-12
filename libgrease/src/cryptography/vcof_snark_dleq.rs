use crate::cryptography::dleq::Dleq;
use crate::cryptography::noir_prover::{InputConverter, NoirProver};
use crate::cryptography::vcof::{
    InvalidProof, NextWitness, ProvingError, VcofPrivateData, VcofPublicData, VerifiableConsecutiveOnewayFunction,
};
use crate::cryptography::vcof_impls::{NoirUpdateCircuit, PoseidonGrumpkinWitness};
use crate::cryptography::witness::ChannelWitnessPublic;
use crate::cryptography::ChannelWitness;
use crate::error::ReadError;
use crate::grease_protocol::utils::Readable;
use ciphersuite::{Ciphersuite, Ed25519};
use grease_grumpkin::Grumpkin;
use log::warn;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use rand_core::OsRng;
use std::io::{Read, Write};
use std::marker::PhantomData;
use zeroize::Zeroize;
use zkuh_rs::noir_api::ProgramArtifact;

/// A VCOF prover for a ZK-SNARK+DLEQ construction using the Grumpkin curve and Poseidon hash.
pub type GP2VcofProver<'p> = SnarkDleqVcofProver<'p, Grumpkin, PoseidonGrumpkinWitness, NoirUpdateCircuit>;

/// A VCOF proof using Snark+DLEQ consists of the ZK-SNARK, _plus_ a DLEQ proof to link the SNARK-friendly curve and Ed25519.
pub struct SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    /// A proof that $P_i, T_i$ correspond such that
    /// $P_i = w_i \cdot G^E$ (Ed25519) and $T_i = w_i \cdot G^{SF}$ (SNARK-friendly curve)
    dleq: <Ed25519 as Dleq<SF>>::Proof,
    /// A SNARK proving that $w_{i+1} = H(update_count, w_i)$, $T_i = w_i \cdot G$ and $T_{i+1} = w_{i+1} \cdot G$.
    snark: Vec<u8>,
}

/// Maximum allowed SNARK proof size (64KB).
///
/// This limit prevents DoS attacks where a malicious actor sends a proof with an
/// enormous length field (e.g., u64::MAX), causing the deserializer to attempt
/// allocating terabytes of memory. Current SNARK proofs are ~16KB, so 64KB provides
/// 4x headroom for future proof system changes while preventing resource exhaustion.
const MAX_SNARK_PROOF_SIZE: u64 = 65_536;

impl<SF> Readable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let dleq =
            <Ed25519 as Dleq<SF>>::read(reader).map_err(|e| ReadError::new("SnarkDleqProof", format!("DLEQ: {e}")))?;
        let snark_len =
            reader.read_u64().map_err(|e| ReadError::new("SnarkDleqProof", format!("SNARK length: {e}")))?;

        // DoS protection: reject unreasonably large SNARK lengths before allocating
        if snark_len > MAX_SNARK_PROOF_SIZE {
            return Err(ReadError::new(
                "SnarkDleqProof",
                format!("SNARK length {snark_len} exceeds maximum allowed size {MAX_SNARK_PROOF_SIZE}"),
            ));
        }

        let mut snark = vec![0u8; snark_len as usize];
        reader.read_exact(&mut snark).map_err(|e| ReadError::new("SnarkDleqProof", format!("SNARK data: {e}")))?;
        Ok(Self { dleq, snark })
    }
}

impl<SF> Writable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.dleq.write(writer)?;
        writer.emit_u64(self.snark.len() as u64)?;
        writer.write_all(&self.snark)
    }
}

/// A Verifiable Consecutive Oneway Function (VCOF) implementation using SNARKs the KeyUpdate function with a DLEQ
/// proof to prove equivalence between the SNARK-friendly curve (SF) and Ed25519.
pub struct SnarkDleqVcofProver<'p, SF, F, C: InputConverter> {
    next_witness: F,
    noir_prover: NoirProver<'p, C>,
    _snark_curve: PhantomData<SF>,
}

impl<'p, SF, V, C> SnarkDleqVcofProver<'p, SF, V, C>
where
    V: NextWitness<W = ChannelWitness<SF>>,
    SF: Curve,
    Ed25519: Dleq<SF>,
    C: InputConverter,
{
    pub fn new(
        checksum: impl Into<String>,
        program: &'p ProgramArtifact,
        converter: &'p C,
    ) -> Result<Self, ProvingError> {
        let noir_prover = NoirProver::new(checksum, program, converter)
            .map_err(|e| ProvingError::init_err(format!("NoirProver initialization error: {e}")))?;
        Ok(Self { next_witness: V::default(), noir_prover, _snark_curve: PhantomData })
    }
}

impl<'p, SF, V, C> VerifiableConsecutiveOnewayFunction for SnarkDleqVcofProver<'p, SF, V, C>
where
    V: NextWitness<W = ChannelWitness<SF>>,
    SF: Curve,
    Ed25519: Dleq<SF>,
    C: InputConverter<Private = SnarkDleqPrivateData<SF>, Public = SnarkDleqPublicData<SF>>,
{
    type Witness = ChannelWitness<SF>;
    type PrivateData = SnarkDleqPrivateData<SF>;
    type PublicData = SnarkDleqPublicData<SF>;
    type Proof = SnarkDleqProof<SF>;
    type Context = ();

    fn compute_next(
        &self,
        update_count: u64,
        prev: &Self::Witness,
        _: &Self::Context,
    ) -> Result<Self::Witness, ProvingError> {
        let result =
            self.next_witness.next_witness(update_count, prev).map_err(|e| ProvingError::derive_err(e.to_string()))?;
        Ok(result)
    }

    fn create_proof(
        &self,
        index: u64,
        private_input: &Self::PrivateData,
        public_input: &Self::PublicData,
        _ctx: &Self::Context,
    ) -> Result<Self::Proof, ProvingError> {
        // generate the DLEQ proof
        let mut rng = OsRng;
        let (dleq, _public_points) = <Ed25519 as Dleq<SF>>::generate_dleq(&mut rng, private_input.next())
            .map_err(|e| ProvingError::prove_err(format!("DLEQ generation error: {}", e)))?;
        // generate the ZK-SNARK proof
        let snark = self
            .noir_prover
            .prove(index, private_input, public_input)
            .map_err(|e| ProvingError::prove_err(format!("NoirProver proof error: {e}")))?;
        // combine into SnarkDleqProof
        Ok(SnarkDleqProof { dleq, snark })
    }

    fn verify(
        &self,
        i: u64,
        public_in: &Self::PublicData,
        proof: &Self::Proof,
        _: &Self::Context,
    ) -> Result<(), InvalidProof> {
        // Verify the DLEQ proof
        let dleq_proof = &proof.dleq;
        Ed25519::verify_dleq(dleq_proof, public_in.next()).map_err(|e| {
            warn!("DLEQ verification failed: {e}");
            InvalidProof::new(i)
        })?;
        // Verify the SNARK proof
        let snark_proof = &proof.snark;
        self.noir_prover.verify(i, public_in, snark_proof).map_err(|e| {
            warn!("SNARK verification failed: {e}");
            InvalidProof::new(i)
        })?;
        Ok(())
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct SnarkDleqPrivateData<SF: Ciphersuite> {
    prev: ChannelWitness<SF>,
    next: ChannelWitness<SF>,
}

impl<SF: Ciphersuite> VcofPrivateData for SnarkDleqPrivateData<SF> {
    type W = ChannelWitness<SF>;

    fn from_parts(prev: Self::W, next: Self::W) -> Self {
        Self { prev, next }
    }

    fn prev(&self) -> &Self::W {
        &self.prev
    }

    fn next(&self) -> &Self::W {
        &self.next
    }
}

#[derive(Clone, Debug)]
pub struct SnarkDleqPublicData<SF: Ciphersuite> {
    prev: ChannelWitnessPublic<SF>,
    next: ChannelWitnessPublic<SF>,
}

impl<SF: Ciphersuite> VcofPublicData for SnarkDleqPublicData<SF> {
    type G = ChannelWitnessPublic<SF>;

    fn from_parts(prev: Self::G, next: Self::G) -> Self {
        Self { prev, next }
    }

    fn prev(&self) -> &Self::G {
        &self.prev
    }

    fn next(&self) -> &Self::G {
        &self.next
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptography::vcof::VerifiableConsecutiveOnewayFunction;
    use crate::cryptography::vcof::{NextWitness, VcofPublicData};
    use crate::cryptography::vcof_impls::PoseidonGrumpkinWitness;
    use crate::cryptography::vcof_impls::{NoirUpdateCircuit, CHECKSUM_UPDATE};
    use crate::cryptography::vcof_snark_dleq::GP2VcofProver;
    use crate::cryptography::witness::Offset;
    use crate::cryptography::ChannelWitness;
    use crate::helpers::xmr_scalar_as_be_hex;
    use grease_grumpkin::ArkPrimeField;
    use grease_grumpkin::Grumpkin;
    use log::info;

    #[test]
    fn update_circuit_noir_matches_rust_implementation() {
        env_logger::try_init().ok();
        // Load the circuit artifact
        let circuit = NoirUpdateCircuit::new().expect("Failed to load NoirUpdateCircuit artifact");
        let prover =
            GP2VcofProver::new(CHECKSUM_UPDATE, circuit.artifact(), &circuit).expect("Failed to create NoirProver");
        // Use the known data from Prover.toml (big-endian hex)
        let scalar_be = hex::decode("004ed0099c91f5472632e7c5ff692f3ef438a3a4d2c1a08f025e931bb708d983").unwrap();
        let w0 = ChannelWitness::<Grumpkin>::try_from_be_bytes(&scalar_be.try_into().unwrap())
            .expect("Failed to create witness from Prover.toml scalar");
        let w0_public = w0.public_points();
        // Log the public points for the transition
        let (x, y) = w0_public.snark_point().as_coordinates_be();
        // Verify point coordinates match Prover.toml
        assert_eq!(
            x, "07052091e5e2778b8da8fba45ac11ee22daeee1c4d0ff93ba741b1e4349a6eff",
            "pub_prev.x mismatch"
        );
        assert_eq!(
            y, "0a6bfe2e7a9c55b01e4c3dd29a93aabb1b68e21d449ebf184010ddd087e2068e",
            "pub_prev.y mismatch"
        );

        // Compute next witness manually to verify
        let next_witness_fn = PoseidonGrumpkinWitness;
        let w1 = next_witness_fn.next_witness(1, &w0).expect("Failed to compute next witness");
        let w1_public = w1.public_points();

        let w1_hex = xmr_scalar_as_be_hex(w1.offset());
        assert_eq!(
            w1_hex, "024f1d193ceff6131819b6da4b541b8d29fcef2d8981eba79116d075240d8c58",
            "w1 mismatch"
        );
        let (p1x, p1y) = w1_public.snark_point().as_coordinates_be();
        assert_eq!(p1x, "04e0f6f4f79db6fc119fc681e9d9319760e9f30ad963e499601e3b10bc876013");
        assert_eq!(p1y, "1d7570ee391669cd88727a40aaa528d8b0aee3cf2918e888fb0a2fed72a72626");

        // Generate a proof for the transition from w0 to w1 (update_count = 1)
        let (proof, public_data) = prover.next(1, &w0, &()).expect("Failed to generate proof");

        info!("SNARK proof size: {} bytes", proof.snark.len());
        info!("VCOF proof generated successfully!");

        let (c1x, c1y) = public_data.next().snark_point().as_coordinates_be();
        assert_eq!(c1x, p1x, "public_data.next x coordinate mismatch");
        assert_eq!(c1y, p1y, "public_data.next y coordinate mismatch");

        prover.verify(1, &public_data, &proof, &()).expect("proof to verify");
        assert!(prover.verify(2, &public_data, &proof, &()).is_err());
    }
}

/// Security test suite for GP2VcofProver
///
/// These tests attempt to break the VCOF proving system by:
/// - Fooling verifiers with proofs where prover doesn't know the witness
/// - Creating valid proofs that fail verification
/// - Generating proofs for non-consecutive witnesses
/// - Finding inputs that cause panics
#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::cryptography::dleq::Dleq;
    use crate::cryptography::vcof::VerifiableConsecutiveOnewayFunction;
    use crate::cryptography::vcof::{ProvingError, VcofPrivateData, VcofPublicData};
    use crate::cryptography::vcof_impls::{NoirUpdateCircuit, CHECKSUM_UPDATE};
    use crate::cryptography::witness::Offset;
    use crate::cryptography::ChannelWitness;
    use crate::grease_protocol::utils::Readable;
    use ciphersuite::Ed25519;
    use grease_grumpkin::Grumpkin;
    use modular_frost::sign::Writable;
    use rand_core::{OsRng, RngCore};
    use std::io::Cursor;

    /// Helper to create a prover for testing
    fn create_prover<'a>(circuit: &'a NoirUpdateCircuit) -> GP2VcofProver<'a> {
        GP2VcofProver::new(CHECKSUM_UPDATE, circuit.artifact(), circuit).expect("Failed to create prover")
    }

    // ==================================================================================
    // SECTION 1: Attempt to fool verifier without knowing the witness
    // ==================================================================================

    /// Attack: Try to create a proof for a witness we don't know by using a different witness
    /// and hoping the DLEQ/SNARK proofs somehow pass.
    #[test]
    fn attack_proof_with_wrong_witness_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        // The "victim" has witness w0 and publishes P0 = w0 * G
        let w0_victim = ChannelWitness::<Grumpkin>::random();
        let w1_victim = prover.compute_next(1, &w0_victim, &()).unwrap();

        // Attacker has a different witness w0_attacker
        let w0_attacker = ChannelWitness::<Grumpkin>::random();
        let w1_attacker = prover.compute_next(1, &w0_attacker, &()).unwrap();

        // Attacker generates a legitimate proof for their own transition
        let (proof_attacker, _) = prover.next(1, &w0_attacker, &()).unwrap();

        // Attacker tries to use their proof with the victim's public points
        let fake_public_data = SnarkDleqPublicData::from_parts(w0_victim.public_points(), w1_victim.public_points());

        // This MUST fail - the DLEQ proof is for a different scalar
        let result = prover.verify(1, &fake_public_data, &proof_attacker, &());
        assert!(result.is_err(), "Verifier should reject proof for wrong public points");
    }

    /// Attack: Generate a DLEQ proof for one scalar but try to use it with different public points
    #[test]
    fn attack_dleq_proof_for_different_scalar_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Create a completely different set of public points
        let w0_fake = ChannelWitness::<Grumpkin>::random();
        let w1_fake = prover.compute_next(1, &w0_fake, &()).unwrap();

        let fake_public_data = SnarkDleqPublicData::from_parts(w0_fake.public_points(), w1_fake.public_points());

        // The DLEQ proof was generated for a different scalar, so this must fail
        let result = prover.verify(1, &fake_public_data, &proof, &());
        assert!(result.is_err(), "DLEQ proof for different scalar must fail");
    }

    /// Attack: Try to create a valid SNARK proof without knowing the private witness
    /// by passing only public inputs to create_proof
    #[test]
    fn attack_snark_without_private_witness_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();

        // Create public data from w0 -> w1
        let public_data = SnarkDleqPublicData::from_parts(w0.public_points(), w1.public_points());

        // But use a WRONG private witness (attacker doesn't know w0)
        let w0_wrong = ChannelWitness::<Grumpkin>::random();
        let w1_wrong = prover.compute_next(1, &w0_wrong, &()).unwrap();
        let private_data = SnarkDleqPrivateData::from_parts(w0_wrong.clone(), w1_wrong);

        // Attempt to create a proof with mismatched private/public data
        // The SNARK should fail because the private witness doesn't match the public points
        let result = prover.create_proof(1, &private_data, &public_data, &());
        assert!(
            result.is_err(),
            "SNARK proof with mismatched private/public data should fail during proving"
        );
    }

    // ==================================================================================
    // SECTION 2: Attempt to generate valid proofs that fail verification
    // ==================================================================================

    /// Test: Ensure a legitimately generated proof always verifies
    #[test]
    fn valid_proof_always_verifies() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        // Generate multiple random proofs and verify they all pass
        for _ in 0..5 {
            let w0 = ChannelWitness::<Grumpkin>::random();
            let (proof, public_data) = prover.next(1, &w0, &()).expect("Proof generation should succeed");
            let result = prover.verify(1, &public_data, &proof, &());
            assert!(result.is_ok(), "Valid proof should always verify: {:?}", result.err());
        }
    }

    /// Test: Chain of proofs all verify correctly
    #[test]
    fn chain_of_proofs_all_verify() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let mut current = ChannelWitness::<Grumpkin>::random();
        for i in 1..=5u64 {
            let (proof, public_data) = prover.next(i, &current, &()).expect("Proof generation should succeed");
            let result = prover.verify(i, &public_data, &proof, &());
            assert!(result.is_ok(), "Chain proof {i} should verify");
            current = prover.compute_next(i, &current, &()).unwrap();
        }
    }

    // ==================================================================================
    // SECTION 3: Attempt to generate proofs for non-consecutive witnesses (j != i+1)
    // ==================================================================================

    /// Attack: Try to skip a step in the chain (w0 -> w2 instead of w0 -> w1)
    #[test]
    fn attack_skip_step_in_chain_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();
        let w2 = prover.compute_next(2, &w1, &()).unwrap();

        // Try to create public data for w0 -> w2 (skipping w1)
        let fake_public_data = SnarkDleqPublicData::from_parts(w0.public_points(), w2.public_points());

        // Create private data for w0 -> w2
        let fake_private_data = SnarkDleqPrivateData::from_parts(w0.clone(), w2.clone());

        // The SNARK circuit should reject this because H(1, w0) != w2
        let result = prover.create_proof(1, &fake_private_data, &fake_public_data, &());
        assert!(result.is_err(), "Should not be able to prove w0 -> w2 directly");
        let result = prover.create_proof(2, &fake_private_data, &fake_public_data, &());
        assert!(result.is_err(), "Should not be able to prove w0 -> w2 directly");
    }

    /// Attack: Try to go backwards in the chain (w1 -> w0)
    #[test]
    fn attack_reverse_direction_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();

        // Try to prove w1 -> w0 (backwards)
        let fake_public_data = SnarkDleqPublicData::from_parts(w1.public_points(), w0.public_points());
        let fake_private_data = SnarkDleqPrivateData::from_parts(w1.clone(), w0.clone());

        // The SNARK should fail because H(1, w1) != w0
        let result = prover.create_proof(1, &fake_private_data, &fake_public_data, &());
        assert!(result.is_err(), "Should not be able to prove reverse direction");
    }

    /// Attack: Use the correct witnesses but wrong index
    #[test]
    fn attack_wrong_index_should_fail_verification() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, public_data) = prover.next(1, &w0, &()).expect("Proof generation should succeed");

        // Verify with wrong indices
        for wrong_index in [0u64, 2, 3, 100, u64::MAX] {
            let result = prover.verify(wrong_index, &public_data, &proof, &());
            assert!(result.is_err(), "Verification with wrong index {wrong_index} should fail");
        }
    }

    /// Attack: Try to use a valid proof from index=1 for index=2
    #[test]
    fn attack_proof_reuse_at_different_index_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();
        let w2 = prover.compute_next(2, &w1, &()).unwrap();

        // Generate proof for index=1 transition
        let (proof_1, _) = prover.next(1, &w0, &()).unwrap();

        // Try to use proof_1 with index=2's public data
        let public_data_2 = SnarkDleqPublicData::from_parts(w1.public_points(), w2.public_points());

        let result = prover.verify(2, &public_data_2, &proof_1, &());
        assert!(result.is_err(), "Proof for index=1 should not work at index=2");
    }

    /// Attack: Create a valid transition for i=2 but claim it's for i=1
    #[test]
    fn attack_mislabel_index_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();

        // Generate proof for i=2 transition (from w1)
        let (proof_2, public_data_2) = prover.next(2, &w1, &()).unwrap();

        // Try to verify at i=1 (wrong index)
        let result = prover.verify(1, &public_data_2, &proof_2, &());
        assert!(result.is_err(), "Proof for i=2 should not verify at i=1");
    }

    /// Test: A valid proof verifies at exactly one index value
    ///
    /// Generate a proof for a random index in [100, 150] and verify it only
    /// passes verification at that exact index, not at any other index in a
    /// wide range around it.
    #[test]
    fn proof_valid_for_unique_index_only() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        // Pick a random index in [100, 150]
        let target_index = 100 + (OsRng.next_u64() % 51); // 100 to 150 inclusive

        // Build chain up to target_index
        let w0 = ChannelWitness::<Grumpkin>::random();
        let mut current = w0.clone();
        for i in 1..target_index {
            current = prover.compute_next(i, &current, &()).unwrap();
        }
        let w_prev = current.clone();

        // Generate proof at target_index
        let (proof, public_data) = prover.next(target_index, &w_prev, &()).expect("Proof should generate");

        // Verify proof works at correct index
        let correct_result = prover.verify(target_index, &public_data, &proof, &());
        assert!(correct_result.is_ok(), "Proof should verify at correct index {target_index}");

        // Scan a range of indices to find if any other index accepts this proof
        let mut valid_indices = vec![];
        for test_index in 75..=175 {
            let result = prover.verify(test_index, &public_data, &proof, &());
            if result.is_ok() {
                valid_indices.push(test_index);
            }
        }

        // Only the target index should accept this proof
        assert_eq!(
            valid_indices.len(),
            1,
            "Proof should only verify at exactly one index, found valid at: {:?}",
            valid_indices
        );
        assert_eq!(
            valid_indices[0], target_index,
            "The only valid index should be the target index {target_index}"
        );
    }

    // ==================================================================================
    // SECTION 4: Test for non-consecutive witness proofs (arbitrary j)
    // ==================================================================================

    /// Attack: Try to create a proof from w_i to w_{i+k} for k > 1
    #[test]
    fn attack_skip_multiple_steps_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let mut current = w0.clone();

        // Compute a chain: w0 -> w1 -> w2 -> w3 -> w4 -> w5
        let mut chain = vec![w0.clone()];
        for i in 1..=5 {
            current = prover.compute_next(i, &current, &()).unwrap();
            chain.push(current.clone());
        }

        // Try to prove w0 -> w_k for various k > 1
        for k in 2..=5 {
            let fake_public_data = SnarkDleqPublicData::from_parts(chain[0].public_points(), chain[k].public_points());
            let fake_private_data = SnarkDleqPrivateData::from_parts(chain[0].clone(), chain[k].clone());

            let result = prover.create_proof(1, &fake_private_data, &fake_public_data, &());
            assert!(result.is_err(), "Should not prove skip from w0 to w{k}");
        }
    }

    /// Attack: Try to prove w_i -> w_j where j < i (backwards jump)
    #[test]
    fn attack_backwards_jump_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let mut current = w0.clone();

        let mut chain = vec![w0.clone()];
        for i in 1..=5 {
            current = prover.compute_next(i, &current, &()).unwrap();
            chain.push(current.clone());
        }

        for i in 1..=5 {
            // Try to prove wi -> w0
            let fake_public_data = SnarkDleqPublicData::from_parts(chain[i].public_points(), chain[0].public_points());
            let fake_private_data = SnarkDleqPrivateData::from_parts(chain[i].clone(), chain[0].clone());

            let result = prover.create_proof(6, &fake_private_data, &fake_public_data, &());
            assert!(result.is_err(), "Should not prove backwards jump from w{i} to w0");
        }
    }

    // ==================================================================================
    // SECTION 5: Proof manipulation attacks
    // ==================================================================================

    /// Attack: Modify the SNARK portion of a valid proof
    #[test]
    fn attack_corrupted_snark_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (mut proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Corrupt some bytes in the SNARK
        if !proof.snark.is_empty() {
            proof.snark[0] ^= 0xFF;
            let mid = proof.snark.len() / 2;
            proof.snark[mid] ^= 0x42;
        }

        let result = prover.verify(1, &public_data, &proof, &());
        assert!(result.is_err(), "Corrupted SNARK should fail verification");
    }

    /// Attack: Swap DLEQ from one proof with SNARK from another
    #[test]
    fn attack_mixed_proof_components_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0_a = ChannelWitness::<Grumpkin>::random();
        let w0_b = ChannelWitness::<Grumpkin>::random();

        let (proof_a, public_data_a) = prover.next(1, &w0_a, &()).unwrap();
        let (proof_b, _) = prover.next(1, &w0_b, &()).unwrap();

        // Create a Frankenstein proof: DLEQ from A, SNARK from B
        let mixed_proof = SnarkDleqProof { dleq: proof_a.dleq.clone(), snark: proof_b.snark.clone() };

        let result = prover.verify(1, &public_data_a, &mixed_proof, &());
        assert!(result.is_err(), "Mixed proof components should fail");

        // Also try the reverse: DLEQ from B, SNARK from A
        let mixed_proof_2 = SnarkDleqProof { dleq: proof_b.dleq.clone(), snark: proof_a.snark.clone() };

        let result = prover.verify(1, &public_data_a, &mixed_proof_2, &());
        assert!(result.is_err(), "Reversed mixed proof should fail");
    }

    /// Attack: Use a valid SNARK with a forged DLEQ for a different point
    #[test]
    fn attack_valid_snark_with_dleq_for_different_point_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (valid_proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Generate a DLEQ proof for a completely different secret
        let other_secret = ChannelWitness::<Grumpkin>::random();
        let mut rng = OsRng;
        let (forged_dleq, _) = <Ed25519 as Dleq<Grumpkin>>::generate_dleq(&mut rng, &other_secret)
            .expect("DLEQ generation should succeed");

        // Combine forged DLEQ with valid SNARK
        let forged_proof = SnarkDleqProof { dleq: forged_dleq, snark: valid_proof.snark.clone() };

        let result = prover.verify(1, &public_data, &forged_proof, &());
        assert!(result.is_err(), "Valid SNARK with forged DLEQ should fail");
    }

    // ==================================================================================
    // SECTION 6: Edge cases and boundary conditions
    // ==================================================================================

    /// Test: Index = 0 should be rejected
    #[test]
    fn index_zero_should_be_rejected() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let result = prover.next(0, &w0, &());

        assert!(result.is_err(), "Index 0 should be rejected");
        if let Err(e) = result {
            match e {
                ProvingError::DerivationError(msg) => {
                    assert!(msg.contains("at least 1"), "Error should mention index constraint");
                }
                _ => panic!("Expected DerivationError, got {:?}", e),
            }
        }
    }

    /// Test: Large index values work correctly
    #[test]
    fn large_index_values_work() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();

        // Test with various large indices
        for &index in &[1000u64, 1_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let result = prover.compute_next(index, &w0, &());
            assert!(result.is_ok(), "Large index {index} should work for compute_next");
        }
    }

    /// Test: Proof generation and verification with u64::MAX index
    #[test]
    fn max_u64_index_works() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let result = prover.next(u64::MAX, &w0, &());

        // Should succeed in generating a proof
        assert!(result.is_ok(), "u64::MAX index should work: {:?}", result.err());

        let (proof, public_data) = result.unwrap();
        let verify_result = prover.verify(u64::MAX, &public_data, &proof, &());
        assert!(verify_result.is_ok(), "Verification at u64::MAX should succeed");
    }

    // ==================================================================================
    // SECTION 7: Serialization and deserialization attacks
    // ==================================================================================

    /// Test: Proof serialization roundtrip
    #[test]
    fn proof_serialization_roundtrip() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Serialize
        let mut serialized = Vec::new();
        proof.write(&mut serialized).expect("Serialization should succeed");

        // Deserialize
        let mut cursor = Cursor::new(&serialized);
        let deserialized = SnarkDleqProof::<Grumpkin>::read(&mut cursor).expect("Deserialization should succeed");

        // Verify the deserialized proof works
        let result = prover.verify(1, &public_data, &deserialized, &());
        assert!(result.is_ok(), "Deserialized proof should verify");
    }

    /// Attack: Truncated proof data
    #[test]
    fn attack_truncated_proof_should_fail_to_deserialize() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, _) = prover.next(1, &w0, &()).unwrap();

        let mut serialized = Vec::new();
        proof.write(&mut serialized).expect("Serialization should succeed");

        // Try various truncation points
        for truncate_at in [1, 10, 50, serialized.len() / 2, serialized.len() - 1] {
            let truncated = &serialized[..truncate_at];
            let mut cursor = Cursor::new(truncated);
            let result = SnarkDleqProof::<Grumpkin>::read(&mut cursor);
            assert!(
                result.is_err(),
                "Truncated proof at {truncate_at} bytes should fail to deserialize"
            );
        }
    }

    /// Attack: Random garbage as proof data
    #[test]
    fn attack_random_garbage_proof_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (_, public_data) = prover.next(1, &w0, &()).unwrap();

        // Generate random bytes of various sizes
        use rand_core::RngCore;
        for size in [100, 1000, 10000, 50000] {
            let mut garbage = vec![0u8; size];
            OsRng.fill_bytes(&mut garbage);

            let mut cursor = Cursor::new(&garbage);
            if let Ok(garbage_proof) = SnarkDleqProof::<Grumpkin>::read(&mut cursor) {
                // Even if parsing succeeds, verification should fail
                let result = prover.verify(1, &public_data, &garbage_proof, &());
                assert!(result.is_err(), "Random garbage proof should not verify");
            }
            // If parsing fails, that's also fine
        }
    }

    /// Attack: Zero-length SNARK in proof
    #[test]
    fn attack_empty_snark_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (valid_proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Create a proof with empty SNARK
        let empty_snark_proof = SnarkDleqProof { dleq: valid_proof.dleq.clone(), snark: vec![] };

        let result = prover.verify(1, &public_data, &empty_snark_proof, &());
        assert!(result.is_err(), "Empty SNARK should fail verification");
    }

    /// DoS Protection: Enormous SNARK length is rejected before allocation
    ///
    /// Previously, the deserializer would read a u64 length and immediately allocate
    /// that many bytes, allowing DoS attacks. Now it validates the length against
    /// MAX_SNARK_PROOF_SIZE before allocating.
    #[test]
    fn dos_protection_rejects_enormous_snark_length() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (valid_proof, _) = prover.next(1, &w0, &()).unwrap();

        // Serialize valid proof to get the DLEQ portion
        let mut serialized = Vec::new();
        valid_proof.write(&mut serialized).expect("Serialization should succeed");

        // Get just the DLEQ bytes (everything before the SNARK length)
        let dleq_end = serialized.len() - 8 - valid_proof.snark.len();
        let mut malicious = serialized[..dleq_end].to_vec();

        // Append an enormous length (1GB) - this would have caused OOM before the fix
        let huge_length: u64 = 1_000_000_000; // 1GB
        malicious.extend_from_slice(&huge_length.to_le_bytes());
        malicious.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Should reject immediately without attempting allocation
        let mut cursor = Cursor::new(&malicious);
        let result = SnarkDleqProof::<Grumpkin>::read(&mut cursor);

        assert!(result.is_err(), "Enormous SNARK length should be rejected");
        if let Err(err) = result {
            assert!(
                err.to_string().contains("exceeds maximum"),
                "Error should mention size limit: {err}"
            );
        }
    }

    /// DoS Protection: u64::MAX length is rejected before allocation
    #[test]
    fn dos_protection_rejects_max_u64_snark_length() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (valid_proof, _) = prover.next(1, &w0, &()).unwrap();

        let mut serialized = Vec::new();
        valid_proof.write(&mut serialized).expect("Serialization should succeed");

        let dleq_end = serialized.len() - 8 - valid_proof.snark.len();
        let mut malicious = serialized[..dleq_end].to_vec();

        // Append u64::MAX - the absolute worst case attack
        malicious.extend_from_slice(&u64::MAX.to_le_bytes());

        let mut cursor = Cursor::new(&malicious);
        let result = SnarkDleqProof::<Grumpkin>::read(&mut cursor);

        assert!(result.is_err(), "u64::MAX SNARK length should be rejected");
    }

    /// Test: Valid proof sizes are still accepted
    #[test]
    fn dos_protection_accepts_valid_proof_sizes() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, _) = prover.next(1, &w0, &()).unwrap();

        // Serialize and deserialize - should work fine
        let mut serialized = Vec::new();
        proof.write(&mut serialized).expect("Serialization should succeed");

        let mut cursor = Cursor::new(&serialized);
        let result = SnarkDleqProof::<Grumpkin>::read(&mut cursor);

        assert!(result.is_ok(), "Valid proof size should be accepted");

        // Verify the SNARK size is well under the MAX_SNARK_PROOF_SIZE limit
        assert!(
            (proof.snark.len() as u64) < MAX_SNARK_PROOF_SIZE,
            "Current SNARK size {} should be under MAX_SNARK_PROOF_SIZE ({} bytes)",
            proof.snark.len(),
            MAX_SNARK_PROOF_SIZE
        );
    }

    // ==================================================================================
    // SECTION 8: Public data manipulation attacks
    // ==================================================================================

    /// Attack: Use legitimate proof with modified public prev point
    #[test]
    fn attack_modified_prev_point_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, _) = prover.next(1, &w0, &()).unwrap();

        // Compute the correct next witness
        let w1 = prover.compute_next(1, &w0, &()).unwrap();

        // Use a different prev point
        let w0_fake = ChannelWitness::<Grumpkin>::random();
        let modified_public_data = SnarkDleqPublicData::from_parts(
            w0_fake.public_points(), // Wrong prev
            w1.public_points(),      // Correct next
        );

        let result = prover.verify(1, &modified_public_data, &proof, &());
        assert!(result.is_err(), "Modified prev point should fail");
    }

    /// Attack: Use legitimate proof with modified public next point
    #[test]
    fn attack_modified_next_point_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, _) = prover.next(1, &w0, &()).unwrap();

        // Use a different next point
        let w1_fake = ChannelWitness::<Grumpkin>::random();
        let modified_public_data = SnarkDleqPublicData::from_parts(
            w0.public_points(),      // Correct prev
            w1_fake.public_points(), // Wrong next
        );

        let result = prover.verify(1, &modified_public_data, &proof, &());
        assert!(result.is_err(), "Modified next point should fail");
    }

    /// Attack: Swap prev and next points
    #[test]
    fn attack_swapped_prev_next_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // Swap prev and next
        let swapped_public_data = SnarkDleqPublicData::from_parts(
            public_data.next().clone(), // next as prev
            public_data.prev().clone(), // prev as next
        );

        let result = prover.verify(1, &swapped_public_data, &proof, &());
        assert!(result.is_err(), "Swapped prev/next should fail");
    }

    // ==================================================================================
    // SECTION 9: DLEQ-SNARK binding tests
    // ==================================================================================

    /// Test that DLEQ binds to the correct Ed25519 point
    #[test]
    fn dleq_binds_to_correct_ed25519_point() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, public_data) = prover.next(1, &w0, &()).unwrap();

        // The DLEQ should be for the next witness, not the prev witness
        // This is verified by checking that verification passes with correct data
        let result = prover.verify(1, &public_data, &proof, &());
        assert!(result.is_ok(), "DLEQ should bind to next witness");
    }

    /// Attack: Generate DLEQ for prev witness instead of next
    #[test]
    fn attack_dleq_for_prev_instead_of_next_should_fail() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let w1 = prover.compute_next(1, &w0, &()).unwrap();

        // Generate DLEQ for w0 (prev) instead of w1 (next)
        let mut rng = OsRng;
        let (wrong_dleq, _) = <Ed25519 as Dleq<Grumpkin>>::generate_dleq(&mut rng, &w0).expect("DLEQ should generate");

        // Get the valid SNARK from a real proof
        let public_data = SnarkDleqPublicData::from_parts(w0.public_points(), w1.public_points());

        // Generate a full proof first to get the SNARK
        let (valid_proof, _) = prover.next(1, &w0, &()).unwrap();

        // Create proof with DLEQ for wrong (prev) witness
        let wrong_proof = SnarkDleqProof { dleq: wrong_dleq, snark: valid_proof.snark.clone() };

        let result = prover.verify(1, &public_data, &wrong_proof, &());
        assert!(result.is_err(), "DLEQ for prev witness should fail verification");
    }

    // ==================================================================================
    // SECTION 10: Identity and special value tests
    // ==================================================================================

    /// Test: Witness derived from small scalar values
    #[test]
    fn small_scalar_witnesses_work() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        // Test with some small scalar values
        for i in 1u64..=10 {
            if let Ok(w0) = ChannelWitness::<Grumpkin>::try_from_snark_scalar(grease_grumpkin::Scalar::from(i)) {
                let result = prover.next(1, &w0, &());
                assert!(result.is_ok(), "Small scalar witness {i} should work: {:?}", result.err());

                let (proof, public_data) = result.unwrap();
                let verify_result = prover.verify(1, &public_data, &proof, &());
                assert!(verify_result.is_ok(), "Small scalar witness {i} proof should verify");
            }
        }
    }

    /// Test: Consecutive proofs from same initial witness but different indices all unique
    #[test]
    fn different_indices_produce_different_outputs() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();

        let w1_idx1 = prover.compute_next(1, &w0, &()).unwrap();
        let w1_idx2 = prover.compute_next(2, &w0, &()).unwrap();
        let w1_idx3 = prover.compute_next(3, &w0, &()).unwrap();

        // All should be different
        assert_ne!(w1_idx1.public_points().snark_point(), w1_idx2.public_points().snark_point());
        assert_ne!(w1_idx2.public_points().snark_point(), w1_idx3.public_points().snark_point());
        assert_ne!(w1_idx1.public_points().snark_point(), w1_idx3.public_points().snark_point());
    }

    // ==================================================================================
    // SECTION 11: Determinism tests
    // ==================================================================================

    /// Test: Same inputs always produce same outputs
    #[test]
    fn proof_generation_is_not_deterministic_due_to_dleq() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();

        let (proof1, public_data1) = prover.next(1, &w0, &()).unwrap();
        let (proof2, public_data2) = prover.next(1, &w0, &()).unwrap();

        // Public data should be identical (deterministic)
        assert_eq!(public_data1.prev().snark_point(), public_data2.prev().snark_point());
        assert_eq!(public_data1.next().snark_point(), public_data2.next().snark_point());

        // DLEQ has randomness, so proofs will differ
        // Just verify both are valid
        assert!(prover.verify(1, &public_data1, &proof1, &()).is_ok());
        assert!(prover.verify(1, &public_data2, &proof2, &()).is_ok());
    }

    /// Test: compute_next is deterministic
    #[test]
    fn compute_next_is_deterministic() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();

        let w1_a = prover.compute_next(1, &w0, &()).unwrap();
        let w1_b = prover.compute_next(1, &w0, &()).unwrap();
        let w1_c = prover.compute_next(1, &w0, &()).unwrap();

        assert_eq!(w1_a.public_points(), w1_b.public_points());
        assert_eq!(w1_b.public_points(), w1_c.public_points());
    }

    // ==================================================================================
    // SECTION 12: Stress and fuzzing-like tests
    // ==================================================================================

    /// Test: Many random proof/verify cycles
    #[test]
    fn stress_test_random_proofs() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        for i in 0..10 {
            let w0 = ChannelWitness::<Grumpkin>::random();
            let index = (i as u64 * 100) + 1; // Varied indices 1, 101, 201, ...

            let result = prover.next(index, &w0, &());
            assert!(result.is_ok(), "Random proof at index {index} should succeed");

            let (proof, public_data) = result.unwrap();
            let verify_result = prover.verify(index, &public_data, &proof, &());
            assert!(
                verify_result.is_ok(),
                "Random proof verification at index {index} should succeed"
            );
        }
    }

    /// Test: Verify that proofs are reasonably sized
    #[test]
    fn proof_size_is_reasonable() {
        let circuit = NoirUpdateCircuit::new().unwrap();
        let prover = create_prover(&circuit);

        let w0 = ChannelWitness::<Grumpkin>::random();
        let (proof, _) = prover.next(1, &w0, &()).unwrap();

        // SNARK proof should be a reasonable size (not empty, not gigantic)
        assert!(!proof.snark.is_empty(), "SNARK proof should not be empty");
        assert!(
            proof.snark.len() < 50_000,
            "SNARK proof should be under 50KB, got {} bytes",
            proof.snark.len()
        );

        // Serialize the full proof
        let mut serialized = Vec::new();
        proof.write(&mut serialized).expect("Serialization should succeed");

        // Full proof includes DLEQ (which is ~44KB for Ed25519/Grumpkin cross-group proof)
        assert!(serialized.len() > proof.snark.len(), "Full proof should include DLEQ");
        assert!(
            serialized.len() < 100_000,
            "Full proof should be under 100KB, got {} bytes",
            serialized.len()
        );
    }
}
