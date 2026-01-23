//! VCOF witness derivation using Grumpkin curve and Poseidon2 hash.
//!
//! This module implements the [`NextWitness`] trait for deriving successive channel
//! witnesses in the Verifiable Consecutive Oneway Function (VCOF) construction.
//!
//! # Overview
//!
//! The VCOF construction allows a prover to demonstrate knowledge of a chain of
//! witnesses `w_0 → w_1 → ... → w_n` where each `w_{i+1} = H(i, w_i)` for a hash
//! function `H`. The witnesses are scalars valid in both the SNARK field (Grumpkin Fr)
//! and Ed25519's scalar field (for Monero compatibility).
//!
//! # Hash Function
//!
//! Uses Poseidon2 over BN254's scalar field for SNARK-friendliness. The hash is
//! computed natively in the Noir circuit, enabling efficient proof generation.
//!
//! # Field Compatibility
//!
//! The main challenge is producing witnesses valid in both:
//! - **Grumpkin Fr** (≈ 2^254): The SNARK scalar field
//! - **Ed25519 scalar field** (≈ 2^252): Required for Monero signatures
//!
//! Since Grumpkin Fr > Ed25519 order, a naive hash output would exceed Ed25519's
//! order ~67% of the time. Two strategies address this:
//!
//! 1. **Native path** ([`next_witness_native`]): Single hash, rejects if out of range.
//!    Suitable for curves where the SNARK field < Ed25519 order.
//!
//! 2. **Wide path** ([`next_witness_wide`]): Combines two hashes (~508 bits) and
//!    reduces mod Ed25519 order. Always succeeds with negligible bias.

use crate::cryptography::vcof::NextWitness;
use crate::cryptography::witness::Offset;
use crate::cryptography::ChannelWitness;
use crate::{Field, XmrScalar};
use acir_field::{AcirField, FieldElement};
use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField as ArkPrimeField};
use ciphersuite::group::ff::PrimeField;
use grease_grumpkin::{Grumpkin, Scalar};
use num_bigint::BigUint;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
#[error("Grumpkin Poseidon VCOF error: {0}")]
pub enum GrumpkinPoseidonVcofError {
    #[error("Incredibly rare occurrence. The next witness is zero, which is not permitted. This channel should be closed immediately.")]
    ZeroWitness,
    #[error("The update count must be greater than zero.")]
    ZeroUpdateCount,
    #[error("Incompatible field orders: {0}")]
    RangeError(String),
    #[error("{0}")]
    Other(String),
}

/// Ed25519 scalar field order (l) in little-endian bytes.
/// l = 2^252 + 27742317777372353535851937790883648493
const ED25519_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Derives the next witness using the optimal strategy for the given SNARK field.
///
/// Automatically selects between the native and wide derivation paths based on
/// the SNARK field's bit width relative to Ed25519's scalar field:
///
/// - If `F::NUM_BITS < Ed25519 bits (253)`: Uses [`next_witness_native`]
/// - Otherwise: Uses [`next_witness_wide`]
///
/// For Grumpkin (254 bits), this always selects the wide path.
///
/// # Type Parameters
///
/// * `F` - The SNARK scalar field type, used to determine derivation strategy
///
/// # Arguments
///
/// * `update_count` - The state index (must be > 0)
/// * `prev` - The previous channel witness to derive from
///
/// # Errors
///
/// - [`GrumpkinPoseidonVcofError::ZeroUpdateCount`] if `update_count == 0`
/// - [`GrumpkinPoseidonVcofError::ZeroWitness`] if the derived witness is zero (probability ~2^{-252})
/// - [`GrumpkinPoseidonVcofError::RangeError`] if using native path and hash exceeds Ed25519 order
pub fn next_witness_auto<F: PrimeField>(
    update_count: u64,
    prev: &ChannelWitness<Grumpkin>,
) -> Result<ChannelWitness<Grumpkin>, GrumpkinPoseidonVcofError> {
    if update_count == 0 {
        return Err(GrumpkinPoseidonVcofError::ZeroUpdateCount);
    }
    let next = if F::NUM_BITS < XmrScalar::NUM_BITS {
        next_witness_native(update_count, prev)
    } else {
        next_witness_wide(update_count, prev)
    }?;
    match next.offset().is_zero().into() {
        true => Err(GrumpkinPoseidonVcofError::ZeroWitness),
        false => Ok(next),
    }
}

/// Converts a FieldElement (acir_field) to ark_bn254::Fr for use with taceo-poseidon2.
fn field_element_to_bn254_fr(fe: FieldElement) -> Bn254Fr {
    Bn254Fr::from_le_bytes_mod_order(&fe.to_le_bytes())
}

/// Converts ark_bn254::Fr back to FieldElement (acir_field).
fn bn254_fr_to_field_element(fr: Bn254Fr) -> FieldElement {
    let bytes: [u8; 32] = fr.into_bigint().to_bytes_le().try_into().expect("Fr is 32 bytes");
    FieldElement::from_le_bytes_reduce(&bytes)
}

/// Computes a Poseidon2 hash matching Noir's `poseidon2::bn254::hash_2`.
///
/// Applies the Poseidon2 t=2 permutation directly and returns the first element.
/// This matches the TaceoLabs noir-poseidon library used by the Noir circuit.
fn poseidon2_hash_2(a: FieldElement, b: FieldElement) -> Result<FieldElement, GrumpkinPoseidonVcofError> {
    let input = [field_element_to_bn254_fr(a), field_element_to_bn254_fr(b)];
    let output = taceo_poseidon2::bn254::t2::permutation(&input);
    Ok(bn254_fr_to_field_element(output[0]))
}

/// Computes a Poseidon2 hash matching Noir's `poseidon2::bn254::hash_3`.
///
/// Applies the Poseidon2 t=3 permutation directly and returns the first element.
/// This matches the TaceoLabs noir-poseidon library used by the Noir circuit.
fn poseidon2_hash_3(
    a: FieldElement,
    b: FieldElement,
    c: FieldElement,
) -> Result<FieldElement, GrumpkinPoseidonVcofError> {
    let input = [field_element_to_bn254_fr(a), field_element_to_bn254_fr(b), field_element_to_bn254_fr(c)];
    let output = taceo_poseidon2::bn254::t3::permutation(&input);
    Ok(bn254_fr_to_field_element(output[0]))
}

/// Converts a Grumpkin scalar (Fr) to a Noir [`FieldElement`] (BN254 Fr).
///
/// # Curve Cycle Relationship
///
/// Grumpkin Fr = BN254 Fq, and BN254 Fr < BN254 Fq. The Poseidon hash operates
/// over BN254 Fr, so we convert the Grumpkin scalar to BN254 Fr using modular
/// reduction (though overflow is rare given the field sizes).
///
/// # Arguments
///
/// * `scalar` - A Grumpkin scalar field element
///
/// # Returns
///
/// A [`FieldElement`] in BN254's scalar field, suitable for Poseidon hashing.
fn scalar_to_field_element(scalar: Scalar) -> FieldElement {
    let le_bytes = scalar.to_repr();
    FieldElement::from_le_bytes_reduce(le_bytes.as_ref())
}

/// Converts a Noir [`FieldElement`] (BN254 Fr) to a Grumpkin scalar (Fr).
///
/// # Curve Cycle Relationship
///
/// - BN254: Fr (scalar) < Fq (base)
/// - Grumpkin: Fr = BN254 Fq, Fq = BN254 Fr
///
/// Since BN254 Fr < BN254 Fq = Grumpkin Fr, any valid BN254 Fr element is
/// automatically a valid Grumpkin Fr element via direct byte reinterpretation.
///
/// # Arguments
///
/// * `fe` - A field element from Poseidon hash output (BN254 Fr)
///
/// # Errors
///
/// Returns [`GrumpkinPoseidonVcofError::RangeError`] if:
/// - The byte representation is too short (should not occur with valid [`FieldElement`])
/// - The value cannot be represented as a Grumpkin scalar (should not occur given field orders)
fn field_element_to_scalar(fe: FieldElement) -> Result<Scalar, GrumpkinPoseidonVcofError> {
    let fq_bn254 = fe.to_le_bytes();
    if fq_bn254.len() < 32 {
        return Err(GrumpkinPoseidonVcofError::RangeError(
            "Hash output too small to convert to Grumpkin Scalar".to_string(),
        ));
    }
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&fq_bn254);
    let fr_grumpkin = Scalar::from_repr(repr).into_option().ok_or_else(|| {
        GrumpkinPoseidonVcofError::RangeError("Failed to convert hash to Grumpkin Scalar".to_string())
    })?;
    Ok(fr_grumpkin)
}

/// Derives the next witness using a single Poseidon2 hash.
///
/// Computes `w_{next} = Poseidon2(update_count, w_{prev})` and attempts to
/// interpret the result as a valid Ed25519 scalar.
///
/// # Warning
///
/// This function should only be used for SNARK curves where the scalar field
/// order is less than Ed25519's order (e.g., BabyJubJub with ~251 bits).
///
/// For Grumpkin (254 bits > Ed25519's 253 bits), this fails ~67% of the time
/// because the hash output exceeds Ed25519's order. Use [`next_witness_wide`]
/// instead for Grumpkin.
///
/// # Arguments
///
/// * `update_count` - The state index for domain separation
/// * `prev` - The previous channel witness
///
/// # Errors
///
/// - [`GrumpkinPoseidonVcofError::RangeError`] if the hash output exceeds Ed25519's scalar order
/// - [`GrumpkinPoseidonVcofError::Other`] if the Poseidon hash computation fails
pub fn next_witness_native(
    update_count: u64,
    prev: &ChannelWitness<Grumpkin>,
) -> Result<ChannelWitness<Grumpkin>, GrumpkinPoseidonVcofError> {
    let update_count_fe = FieldElement::from(update_count);
    let prev_fe = scalar_to_field_element(prev.as_snark_scalar());

    // Hash using direct permutation matching Noir's poseidon2::bn254::hash_2
    let hash = poseidon2_hash_2(update_count_fe, prev_fe)?;
    let fr_grumpkin = field_element_to_scalar(hash)?;
    ChannelWitness::try_from_snark_scalar(fr_grumpkin).map_err(|_| {
        GrumpkinPoseidonVcofError::RangeError(
            "Hash result exceeds Ed25519 order - use next_witness_wide for Grumpkin".to_string(),
        )
    })
}

/// Derives the next witness using wide Poseidon2 output reduced mod Ed25519 order.
///
/// Computes two Poseidon2 hashes with domain separation and combines them into
/// a ~508-bit value, then reduces mod Ed25519's scalar order. This guarantees
/// a valid output regardless of SNARK field size.
///
/// # Algorithm
///
/// ```text
/// h0 = Poseidon2(update_count, w_prev, 0)
/// h1 = Poseidon2(update_count, w_prev, 1)
/// wide = h0 + h1 * 2^254
/// w_next = wide mod ℓ  (where ℓ is Ed25519's scalar order)
/// ```
///
/// # Bias Analysis
///
/// The wide value has ~508 bits of entropy. After reduction mod ℓ (~253 bits),
/// the statistical distance from uniform is bounded by 2^(508-253)/ℓ ≈ 2^{-254},
/// which is cryptographically negligible.
///
/// # Arguments
///
/// * `update_count` - The state index for domain separation
/// * `prev` - The previous channel witness
///
/// # Errors
///
/// - [`GrumpkinPoseidonVcofError::Other`] if Poseidon hash computation fails
/// - [`GrumpkinPoseidonVcofError::RangeError`] if byte conversion fails (should not occur)
pub fn next_witness_wide(
    update_count: u64,
    prev: &ChannelWitness<Grumpkin>,
) -> Result<ChannelWitness<Grumpkin>, GrumpkinPoseidonVcofError> {
    let update_count_fe = FieldElement::from(update_count);
    let prev_fe = scalar_to_field_element(prev.as_snark_scalar());

    // Two Poseidon2 hashes with domain separation matching Noir's poseidon2::bn254::hash_3
    let h0 = poseidon2_hash_3(update_count_fe, prev_fe, FieldElement::zero())?;
    let h1 = poseidon2_hash_3(update_count_fe, prev_fe, FieldElement::one())?;

    let h0_big = BigUint::from(h0.into_repr());
    let h1_big = BigUint::from(h1.into_repr());
    let ed25519_order = BigUint::from_bytes_le(&ED25519_ORDER_LE);

    // Compute wide = h0 + h1 * 2^254
    let shift = BigUint::from(1u64) << 254;
    let wide = &h0_big + &h1_big * &shift;

    // Reduce mod Ed25519 order
    let reduced: BigUint = wide % &ed25519_order;

    // Convert back to ChannelWitness
    let reduced_bytes = reduced.to_bytes_le();
    let mut result_bytes = [0u8; 32];
    let copy_len = reduced_bytes.len().min(32);
    result_bytes[..copy_len].copy_from_slice(&reduced_bytes[..copy_len]);

    ChannelWitness::try_from_le_bytes(&result_bytes).map_err(|_| {
        GrumpkinPoseidonVcofError::RangeError("Failed to create ChannelWitness from reduced hash".to_string())
    })
}

/// Stateless [`NextWitness`] implementation using Poseidon2 over Grumpkin.
///
/// This is the production implementation for Grease payment channels. It uses
/// [`next_witness_auto`] with the Grumpkin scalar field, which selects the
/// wide derivation path for correct handling of field size differences.
///
/// # Example
///
/// ```ignore
/// use crate::cryptography::vcof::NextWitness;
/// use crate::cryptography::vcof_impls::PoseidonGrumpkinWitness;
///
/// let vcof = PoseidonGrumpkinWitness;
/// let w0 = ChannelWitness::<Grumpkin>::random();
/// let w1 = vcof.next_witness(1, &w0)?;
/// let w2 = vcof.next_witness(2, &w1)?;
/// ```
#[derive(Default, Clone)]
pub struct PoseidonGrumpkinWitness;

impl NextWitness for PoseidonGrumpkinWitness {
    type W = ChannelWitness<Grumpkin>;
    type Err = GrumpkinPoseidonVcofError;

    /// Derives the next channel witness from the previous one.
    ///
    /// Delegates to [`next_witness_auto`] with `F = Grumpkin::Scalar`, which
    /// uses the wide derivation path for unbiased Ed25519-compatible output.
    ///
    /// # Arguments
    ///
    /// * `update_count` - The state index (must be > 0, monotonically increasing)
    /// * `prev` - The previous witness in the chain
    ///
    /// # Errors
    ///
    /// See [`next_witness_auto`] for error conditions.
    fn next_witness(&self, update_count: u64, prev: &Self::W) -> Result<Self::W, Self::Err> {
        next_witness_auto::<Scalar>(update_count, prev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::xmr_scalar_as_be_hex;
    use ciphersuite::group::ff::Field;
    use num_traits::Zero;

    /// Ed25519 scalar field order (l) as a BigUint for comparison.
    fn ed25519_order() -> BigUint {
        BigUint::from_bytes_le(&ED25519_ORDER_LE)
    }

    /// BN254 scalar field order (r) - this is Grumpkin's base field Fq.
    fn bn254_r() -> BigUint {
        BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }

    /// BN254 base field order (q) - this is Grumpkin's scalar field Fr.
    fn bn254_q() -> BigUint {
        BigUint::parse_bytes(
            b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap()
    }

    // ==================== Constant Verification Tests ====================

    #[test]
    fn ed25519_order_constant_is_correct() {
        // Ed25519 order l = 2^252 + 27742317777372353535851937790883648493
        let expected = BigUint::from(1u64) << 252;
        let offset = BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap();
        let expected = expected + offset;

        assert_eq!(
            ed25519_order(),
            expected,
            "ED25519_ORDER_LE should represent l = 2^252 + 27742317777372353535851937790883648493"
        );
    }

    #[test]
    fn ed25519_order_has_correct_bit_length() {
        let order = ed25519_order();
        // Ed25519 order is slightly larger than 2^252, so it has 253 bits
        assert_eq!(order.bits(), 253, "Ed25519 order should be 253 bits");
    }

    // ==================== Field Order Relationship Tests ====================

    #[test]
    fn bn254_r_less_than_q() {
        // The docstring claims: "For BN254, r < q"
        let r = bn254_r();
        let q = bn254_q();
        assert!(r < q, "BN254 scalar field r should be less than base field q");
    }

    #[test]
    fn grumpkin_scalar_field_larger_than_ed25519() {
        // The docstring claims: "N_grumpkin > N_ed25519" (Grumpkin scalar field > Ed25519 order)
        // Grumpkin Fr = BN254 Fq
        let grumpkin_fr = bn254_q();
        let ed25519_l = ed25519_order();

        assert!(
            grumpkin_fr > ed25519_l,
            "Grumpkin scalar field (BN254 q) should be larger than Ed25519 order"
        );

        // Quantify the ratio: Grumpkin Fr / Ed25519 l ≈ 3.0
        // This means random Grumpkin scalars will exceed Ed25519 order ~67% of the time
        let ratio = &grumpkin_fr / &ed25519_l;
        assert!(ratio >= BigUint::from(3u32), "Grumpkin Fr should be at least 3x Ed25519 order");
    }

    #[test]
    fn grumpkin_fr_and_bn254_q_are_same() {
        // Verify the curve cycle relationship: Grumpkin Fr = BN254 Fq
        let grumpkin_fr_str = grease_grumpkin::constants::MODULUS_STR_FR;
        let bn254_q = bn254_q();
        let grumpkin_fr = BigUint::parse_bytes(grumpkin_fr_str.as_bytes(), 10).unwrap();

        assert_eq!(grumpkin_fr, bn254_q, "Grumpkin Fr should equal BN254 base field q");
    }

    // ==================== scalar_to_field_element Tests ====================

    #[test]
    fn scalar_to_field_element_zero() {
        let zero = Scalar::ZERO;
        let fe = scalar_to_field_element(zero);
        assert!(fe.is_zero(), "Zero scalar should convert to zero FieldElement");
    }

    #[test]
    fn scalar_to_field_element_one() {
        let one = Scalar::ONE;
        let fe = scalar_to_field_element(one);
        assert!(fe.is_one(), "One scalar should convert to one FieldElement");
    }

    #[test]
    fn scalar_to_field_element_small_values() {
        for i in 0u64..100 {
            let scalar = Scalar::from(i);
            let fe = scalar_to_field_element(scalar);
            let expected = FieldElement::from(i);
            assert_eq!(fe, expected, "Small value {i} should convert correctly");
        }
    }

    // ==================== field_element_to_scalar Tests ====================

    #[test]
    fn field_element_to_scalar_zero() {
        let zero = FieldElement::zero();
        let scalar = field_element_to_scalar(zero).expect("Zero should convert");
        assert_eq!(scalar, Scalar::ZERO, "Zero FieldElement should convert to zero Scalar");
    }

    #[test]
    fn field_element_to_scalar_one() {
        let one = FieldElement::one();
        let scalar = field_element_to_scalar(one).expect("One should convert");
        assert_eq!(scalar, Scalar::ONE, "One FieldElement should convert to one Scalar");
    }

    #[test]
    fn field_element_to_scalar_small_values() {
        for i in 0u64..100 {
            let fe = FieldElement::from(i);
            let scalar = field_element_to_scalar(fe).expect("Small value should convert");
            let expected = Scalar::from(i);
            assert_eq!(scalar, expected, "Small value {i} should convert correctly");
        }
    }

    #[test]
    fn scalar_field_element_roundtrip_small_values() {
        // Small values should round-trip perfectly
        for i in 0u64..1000 {
            let original = Scalar::from(i);
            let fe = scalar_to_field_element(original);
            let back = field_element_to_scalar(fe).expect("Should convert back");
            assert_eq!(original, back, "Value {i} should round-trip");
        }
    }

    // ==================== next_witness_native Tests ====================

    #[test]
    fn next_witness_native_error_message_suggests_wide() {
        // When native fails, the error message should guide users to use wide
        let witness = ChannelWitness::<Grumpkin>::random();

        // Keep trying until we get a failure (should happen quickly)
        for i in 1..100 {
            if let Err(e) = next_witness_native(i, &witness) {
                let msg = e.to_string();
                assert!(
                    msg.contains("next_witness_wide"),
                    "Error should recommend next_witness_wide: {msg}"
                );
                return;
            }
        }
        panic!("Expected at least one failure in 100 trials");
    }

    #[test]
    fn next_witness_native_succeeds_for_small_hash_outputs() {
        // With specific inputs, the hash might produce a small enough value
        // This test verifies that success IS possible (not guaranteed due to hash unpredictability)
        let mut successes = 0;

        for i in 0..1000 {
            let witness = ChannelWitness::<Grumpkin>::random();
            if next_witness_native(i + 1, &witness).is_ok() {
                successes += 1;
            }
        }

        assert!(
            successes > 0,
            "Expected at least some successes in 1000 trials, got {successes}"
        );
    }

    // ==================== next_witness_wide Tests ====================

    #[test]
    fn next_witness_wide_always_succeeds() {
        // The wide version should always succeed
        for i in 0..1000 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_wide(i + 1, &witness);
            assert!(
                result.is_ok(),
                "next_witness_wide should always succeed, failed at iteration {i}"
            );
        }
    }

    #[test]
    fn next_witness_wide_produces_valid_ed25519_scalars() {
        // Results should always be valid Ed25519 scalars (< Ed25519 order)
        for i in 0..100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_wide(i + 1, &witness).expect("Should succeed");

            // The ChannelWitness type guarantees validity in both fields
            // Verify by checking we can access the offset
            let _offset = result.offset();

            // Also verify the bytes represent a value < Ed25519 order
            let bytes = result.to_le_bytes();
            let value = BigUint::from_bytes_le(&bytes);
            assert!(value < ed25519_order(), "Result should be less than Ed25519 order");
        }
    }

    #[test]
    fn next_witness_wide_produces_nonzero_results() {
        // The wide version handles zero defensively, but zero should be extremely unlikely
        for i in 0..1000 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_wide(i + 1, &witness).expect("Should succeed");
            let bytes = result.to_le_bytes();
            let value = BigUint::from_bytes_le(&bytes);

            assert!(!value.is_zero(), "Result should not be zero (iteration {i})");
        }
    }

    // ==================== Determinism Tests ====================

    #[test]
    fn next_witness_wide_is_deterministic() {
        let witness = ChannelWitness::<Grumpkin>::random();

        for update_count in 1..10 {
            let result1 = next_witness_wide(update_count, &witness).expect("Should succeed");
            let result2 = next_witness_wide(update_count, &witness).expect("Should succeed");

            assert_eq!(
                result1.to_le_bytes(),
                result2.to_le_bytes(),
                "Same inputs should produce same output for update_count={update_count}"
            );
        }
    }

    #[test]
    fn different_update_counts_produce_different_results() {
        let witness = ChannelWitness::<Grumpkin>::random();

        let result1 = next_witness_wide(1, &witness).expect("Should succeed");
        let result2 = next_witness_wide(2, &witness).expect("Should succeed");
        let result3 = next_witness_wide(3, &witness).expect("Should succeed");

        assert_ne!(
            result1.to_le_bytes(),
            result2.to_le_bytes(),
            "Different update counts should produce different results"
        );
        assert_ne!(
            result2.to_le_bytes(),
            result3.to_le_bytes(),
            "Different update counts should produce different results"
        );
        assert_ne!(
            result1.to_le_bytes(),
            result3.to_le_bytes(),
            "Different update counts should produce different results"
        );
    }

    #[test]
    fn different_witnesses_produce_different_results() {
        let witness1 = ChannelWitness::<Grumpkin>::random();
        let witness2 = ChannelWitness::<Grumpkin>::random();

        // Very unlikely to be equal
        if witness1.to_le_bytes() != witness2.to_le_bytes() {
            let result1 = next_witness_wide(1, &witness1).expect("Should succeed");
            let result2 = next_witness_wide(1, &witness2).expect("Should succeed");

            assert_ne!(
                result1.to_le_bytes(),
                result2.to_le_bytes(),
                "Different witnesses should produce different results"
            );
        }
    }

    // ==================== Chain Derivation Tests ====================

    #[test]
    fn can_derive_chain_of_witnesses() {
        // Test that we can derive a chain of witnesses
        let mut current = ChannelWitness::<Grumpkin>::random();
        let mut witnesses = vec![current];

        for i in 1..=100 {
            current = next_witness_wide(i, &current).expect("Chain derivation should succeed");
            witnesses.push(current);
        }

        // All witnesses should be unique
        for (i, w1) in witnesses.iter().enumerate() {
            for (j, w2) in witnesses.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        w1.to_le_bytes(),
                        w2.to_le_bytes(),
                        "Witnesses at positions {i} and {j} should be different"
                    );
                }
            }
        }
    }

    #[test]
    fn chain_derivation_is_deterministic() {
        let initial = ChannelWitness::<Grumpkin>::random();

        // Derive chain twice
        let mut chain1 = vec![initial];
        let mut chain2 = vec![initial];

        let mut current1 = initial;
        let mut current2 = initial;

        for i in 1..=10 {
            current1 = next_witness_wide(i, &current1).expect("Should succeed");
            current2 = next_witness_wide(i, &current2).expect("Should succeed");
            chain1.push(current1);
            chain2.push(current2);
        }

        for (i, (w1, w2)) in chain1.iter().zip(chain2.iter()).enumerate() {
            assert_eq!(w1.to_le_bytes(), w2.to_le_bytes(), "Chain position {i} should match");
        }
    }

    // ==================== Edge Case Tests ====================

    #[test]
    fn update_count_max_works() {
        let witness = ChannelWitness::<Grumpkin>::random();
        let result = next_witness_wide(u64::MAX, &witness);
        assert!(result.is_ok(), "update_count=u64::MAX should work");
    }

    #[test]
    fn update_count_zero_is_rejected() {
        let witness = ChannelWitness::<Grumpkin>::random();
        // update_count=0 should work (no validation in the current implementation)
        let result = next_witness_auto::<Scalar>(0, &witness);
        assert!(result.is_err(), "update_count=0 should not work");
    }

    #[test]
    fn witness_from_small_value_works() {
        // Create a witness from a small scalar value
        let small_scalar = Scalar::from(42u64);
        let witness =
            ChannelWitness::<Grumpkin>::try_from_snark_scalar(small_scalar).expect("Small scalar should be valid");

        let result = next_witness_wide(1, &witness);
        assert!(result.is_ok(), "Witness from small value should work");
    }

    // ==================== Wide Reduction Algorithm Tests ====================

    #[test]
    fn wide_reduction_uses_domain_separation() {
        // The wide function uses two hashes with different domain separators (0 and 1)
        // This test verifies the domain separation works by checking that h0 != h1 for same input
        let witness = ChannelWitness::<Grumpkin>::random();
        let update_count_fe = FieldElement::from(1u64);
        let prev_fe = scalar_to_field_element(witness.as_snark_scalar());

        let h0 = poseidon2_hash_3(update_count_fe, prev_fe, FieldElement::zero()).expect("Hash should succeed");
        let h1 = poseidon2_hash_3(update_count_fe, prev_fe, FieldElement::one()).expect("Hash should succeed");

        assert_ne!(h0, h1, "Hashes with different domain separators should differ");
    }

    #[test]
    fn wide_reduction_produces_approximately_uniform_distribution() {
        // Statistical test: results should be roughly uniformly distributed
        // We check that the high bytes aren't all the same (which would indicate bias)
        let mut high_bytes = std::collections::HashSet::new();

        for i in 0..100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_wide(i + 1, &witness).expect("Should succeed");
            let bytes = result.to_le_bytes();
            high_bytes.insert(bytes[31]);
        }

        // With uniform distribution over Ed25519 order, the high byte (in LE) can be 0x00-0x10
        // We expect some variety
        assert!(
            high_bytes.len() > 1,
            "Should have variety in high bytes, got only {:?}",
            high_bytes
        );
    }

    #[test]
    fn known_input() {
        // Test with a known input/output pair for wide reduction
        let w0_be = "0x004ed0099c91f5472632e7c5ff692f3ef438a3a4d2c1a08f025e931bb708d983";
        let w1_be = "0x024f1d193ceff6131819b6da4b541b8d29fcef2d8981eba79116d075240d8c58";

        let str_to_bytes = |s: &str| {
            let s = s.trim_start_matches("0x");
            let mut bytes = [0u8; 32];
            let decoded = hex::decode(s).expect("Hex decode failed");
            let copy_len = decoded.len().min(32);
            bytes.copy_from_slice(&decoded[..copy_len]);
            bytes.reverse();
            bytes
        };

        let witness = ChannelWitness::<Grumpkin>::try_from_le_bytes(&str_to_bytes(w0_be))
            .expect("Should create witness from bytes");
        println!("{}", xmr_scalar_as_be_hex(&witness.offset()));
        let result = next_witness_wide(1, &witness).expect("Should succeed");
        let mut result_bytes = result.to_le_bytes();
        result_bytes.reverse();
        let actual = format!("0x{}", hex::encode(&result_bytes));
        assert_eq!(actual, w1_be);
    }

    // ==================== Automatic Algorithm Selection Tests ====================

    #[test]
    fn next_witness_selects_wide_for_grumpkin_scalar() {
        // Grumpkin scalar has 254 bits > Ed25519's 253 bits, so should use wide path
        // Wide path always succeeds
        for i in 1..=100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_auto::<Scalar>(i, &witness);
            assert!(result.is_ok(), "next_witness<Scalar> should always succeed (uses wide path)");

            // Verify it produces the same result as next_witness_wide
            let wide_result = next_witness_wide(i, &witness).expect("Wide should succeed");
            assert_eq!(
                result.unwrap().to_le_bytes(),
                wide_result.to_le_bytes(),
                "next_witness<Scalar> should match next_witness_wide"
            );
        }
    }

    #[test]
    fn next_witness_with_babyjubjub_matches_native() {
        // When using BabyJubJub (smaller field), results should match next_witness_native
        use grease_babyjubjub::Scalar as BjjScalar;

        for i in 1..100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let auto_result = next_witness_auto::<BjjScalar>(i, &witness);
            let native_result = next_witness_native(i, &witness);

            // Both should have the same outcome (success or failure)
            assert_eq!(
                auto_result.is_ok(),
                native_result.is_ok(),
                "next_witness<BjjScalar> should match next_witness_native success/failure"
            );

            // If both succeeded, values should match
            if let (Ok(auto), Ok(native)) = (auto_result, native_result) {
                assert_eq!(
                    auto.to_le_bytes(),
                    native.to_le_bytes(),
                    "next_witness<BjjScalar> should match next_witness_native value"
                );
            }
        }
    }

    #[test]
    fn next_witness_with_ed25519_scalar_uses_wide() {
        // Ed25519 scalar has 253 bits = Ed25519's 253 bits (equal, not less than)
        // So it should use the wide path (>= threshold)
        for i in 1..=100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_auto::<XmrScalar>(i, &witness);

            // Wide path always succeeds
            assert!(result.is_ok(), "next_witness<XmrScalar> should always succeed (uses wide path)");

            // Verify it matches wide path
            let wide_result = next_witness_wide(i, &witness).expect("Wide should succeed");
            assert_eq!(
                result.unwrap().to_le_bytes(),
                wide_result.to_le_bytes(),
                "next_witness<XmrScalar> should match next_witness_wide"
            );
        }
    }

    #[test]
    fn next_witness_rejects_zero_update_count() {
        // The new validation should reject update_count == 0
        let witness = ChannelWitness::<Grumpkin>::random();

        let result = next_witness_auto::<Scalar>(0, &witness);
        assert!(matches!(result.unwrap_err(), GrumpkinPoseidonVcofError::ZeroUpdateCount));
    }

    #[test]
    fn next_witness_zero_rejection_applies_to_all_field_types() {
        // Zero rejection should apply regardless of field type parameter
        use grease_babyjubjub::Scalar as BjjScalar;
        let witness = ChannelWitness::<Grumpkin>::random();

        // With Grumpkin scalar (wide path)
        assert!(
            next_witness_auto::<Scalar>(0, &witness).is_err(),
            "Should reject zero with Grumpkin scalar"
        );

        // With BabyJubJub scalar (native path)
        assert!(
            next_witness_auto::<BjjScalar>(0, &witness).is_err(),
            "Should reject zero with BabyJubJub scalar"
        );

        // With Ed25519 scalar
        assert!(
            next_witness_auto::<XmrScalar>(0, &witness).is_err(),
            "Should reject zero with Ed25519 scalar"
        );
    }
}
