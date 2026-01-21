//! Concrete VCOF implementation using
//! * Grumpkin curve and
//! * Poseidon2 hash function.

use crate::cryptography::ChannelWitness;
use crate::{Field, XmrScalar};
use acir_field::{AcirField, FieldElement};
use bn254_blackbox_solver::poseidon_hash;
use ciphersuite::group::ff::PrimeField;
use grease_grumpkin::{Grumpkin, Scalar};
use num_bigint::BigUint;
use num_traits::Zero;
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

/// Convenience function for Grumpkin - uses the wide reduction path.
///
/// This is the appropriate choice for Grumpkin since N_grumpkin > N_ed25519.
pub fn next_witness<F: PrimeField>(
    update_count: u64,
    prev: ChannelWitness<Grumpkin>,
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

/// Converts a Grumpkin Scalar (BN254 Fq) to a FieldElement (BN254 Fr).
/// Since Fr < Fq, this uses reducing conversion for safety.
fn scalar_to_field_element(scalar: Scalar) -> FieldElement {
    let le_bytes = scalar.to_repr();
    FieldElement::from_le_bytes_reduce(le_bytes.as_ref())
}

/// For BN254, r < q. Notably, since we're interested in a Grumpkin Fr element, we can note the following:
/// In Grumpkin, Fq = Fr(BN254) and Fr = Fq(BN254).
/// Thus, we can reinterpret the BN254 Fr element as a BN254 Fq element directly, and then treat it as a Grumpkin Scalar since q < r
/// in Grumpkin.
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

/// Derives the next witness using a single Poseidon2 hash (Grumpkin version).
///
/// **WARNING**: This function should only be used for SNARK curves where N_SF < N_ed25519
/// (e.g., BabyJubJub). For Grumpkin (where N_SF > N_ed25519), use `next_witness_wide` instead.
///
/// When used with Grumpkin, this function will fail ~75% of the time because the hash
/// output exceeds Ed25519's order. It is provided for API completeness and testing.
pub fn next_witness_native(
    update_count: u64,
    prev: ChannelWitness<Grumpkin>,
) -> Result<ChannelWitness<Grumpkin>, GrumpkinPoseidonVcofError> {
    let update_count_fe = FieldElement::from(update_count);
    let prev_fe = scalar_to_field_element(prev.as_snark_scalar());

    // hash is an  element on BN254's Scalar Field (Fr).
    let hash =
        poseidon_hash(&[update_count_fe, prev_fe]).map_err(|e| GrumpkinPoseidonVcofError::Other(e.to_string()))?;
    let fr_grumpkin = field_element_to_scalar(hash)?;
    ChannelWitness::try_from_snark_scalar(fr_grumpkin).map_err(|_| {
        GrumpkinPoseidonVcofError::RangeError(
            "Hash result exceeds Ed25519 order - use next_witness_wide for Grumpkin".to_string(),
        )
    })
}

/// Derives the next witness using wide Poseidon2 output reduced mod Ed25519 order.
///
/// Use this for SNARK curves where N_SF > N_ed25519 (e.g., Grumpkin).
/// Combines two Poseidon2 hash outputs (~508 bits) and reduces mod Ed25519 order
/// to produce a cryptographically unbiased result valid in both fields.
///
/// # Bias
/// Statistical distance from uniform is ~2^(-254), cryptographically negligible.
pub fn next_witness_wide(
    update_count: u64,
    prev: ChannelWitness<Grumpkin>,
) -> Result<ChannelWitness<Grumpkin>, GrumpkinPoseidonVcofError> {
    let update_count_fe = FieldElement::from(update_count);
    let prev_fe = scalar_to_field_element(prev.as_snark_scalar());
    let zero_fe = FieldElement::zero();
    let one_fe = FieldElement::one();
    // Two Poseidon hashes with domain separation (matching Noir's hash_3)
    let h0 = poseidon_hash(&[update_count_fe, prev_fe, zero_fe])
        .map_err(|e| GrumpkinPoseidonVcofError::Other(e.to_string()))?;
    let h1 = poseidon_hash(&[update_count_fe, prev_fe, one_fe])
        .map_err(|e| GrumpkinPoseidonVcofError::Other(e.to_string()))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ed25519;
    use grease_babyjubjub::{BabyJubJub, BjjPoint};

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
            if let Err(e) = next_witness_native(i, witness) {
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
            if next_witness_native(i + 1, witness).is_ok() {
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
            let result = next_witness_wide(i + 1, witness);
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
            let result = next_witness_wide(i + 1, witness).expect("Should succeed");

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
            let result = next_witness_wide(i + 1, witness).expect("Should succeed");
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
            let result1 = next_witness_wide(update_count, witness).expect("Should succeed");
            let result2 = next_witness_wide(update_count, witness).expect("Should succeed");

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

        let result1 = next_witness_wide(1, witness).expect("Should succeed");
        let result2 = next_witness_wide(2, witness).expect("Should succeed");
        let result3 = next_witness_wide(3, witness).expect("Should succeed");

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
            let result1 = next_witness_wide(1, witness1).expect("Should succeed");
            let result2 = next_witness_wide(1, witness2).expect("Should succeed");

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
            current = next_witness_wide(i, current).expect("Chain derivation should succeed");
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
            current1 = next_witness_wide(i, current1).expect("Should succeed");
            current2 = next_witness_wide(i, current2).expect("Should succeed");
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
        let result = next_witness_wide(u64::MAX, witness);
        assert!(result.is_ok(), "update_count=u64::MAX should work");
    }

    #[test]
    fn update_count_zero_is_rejected() {
        let witness = ChannelWitness::<Grumpkin>::random();
        // update_count=0 should work (no validation in the current implementation)
        let result = next_witness::<Scalar>(0, witness);
        assert!(result.is_err(), "update_count=0 should not work");
    }

    #[test]
    fn witness_from_small_value_works() {
        // Create a witness from a small scalar value
        let small_scalar = Scalar::from(42u64);
        let witness =
            ChannelWitness::<Grumpkin>::try_from_snark_scalar(small_scalar).expect("Small scalar should be valid");

        let result = next_witness_wide(1, witness);
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

        let h0 = poseidon_hash(&[update_count_fe, prev_fe, FieldElement::zero()]).expect("Hash should succeed");
        let h1 = poseidon_hash(&[update_count_fe, prev_fe, FieldElement::one()]).expect("Hash should succeed");

        assert_ne!(h0, h1, "Hashes with different domain separators should differ");
    }

    #[test]
    fn wide_reduction_produces_approximately_uniform_distribution() {
        // Statistical test: results should be roughly uniformly distributed
        // We check that the high bytes aren't all the same (which would indicate bias)
        let mut high_bytes = std::collections::HashSet::new();

        for i in 0..100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness_wide(i + 1, witness).expect("Should succeed");
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

    // ==================== Automatic Algorithm Selection Tests ====================

    #[test]
    fn next_witness_selects_wide_for_grumpkin_scalar() {
        // Grumpkin scalar has 254 bits > Ed25519's 253 bits, so should use wide path
        // Wide path always succeeds
        for i in 1..=100 {
            let witness = ChannelWitness::<Grumpkin>::random();
            let result = next_witness::<Scalar>(i, witness);
            assert!(result.is_ok(), "next_witness<Scalar> should always succeed (uses wide path)");

            // Verify it produces the same result as next_witness_wide
            let wide_result = next_witness_wide(i, witness).expect("Wide should succeed");
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
            let auto_result = next_witness::<BjjScalar>(i, witness);
            let native_result = next_witness_native(i, witness);

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
            let result = next_witness::<XmrScalar>(i, witness);

            // Wide path always succeeds
            assert!(result.is_ok(), "next_witness<XmrScalar> should always succeed (uses wide path)");

            // Verify it matches wide path
            let wide_result = next_witness_wide(i, witness).expect("Wide should succeed");
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

        let result = next_witness::<Scalar>(0, witness);
        assert!(matches!(result.unwrap_err(), GrumpkinPoseidonVcofError::ZeroUpdateCount));
    }

    #[test]
    fn next_witness_zero_rejection_applies_to_all_field_types() {
        // Zero rejection should apply regardless of field type parameter
        use grease_babyjubjub::Scalar as BjjScalar;
        let witness = ChannelWitness::<Grumpkin>::random();

        // With Grumpkin scalar (wide path)
        assert!(
            next_witness::<Scalar>(0, witness).is_err(),
            "Should reject zero with Grumpkin scalar"
        );

        // With BabyJubJub scalar (native path)
        assert!(
            next_witness::<BjjScalar>(0, witness).is_err(),
            "Should reject zero with BabyJubJub scalar"
        );

        // With Ed25519 scalar
        assert!(
            next_witness::<XmrScalar>(0, witness).is_err(),
            "Should reject zero with Ed25519 scalar"
        );
    }
}
