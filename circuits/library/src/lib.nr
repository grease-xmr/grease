use dep::bignum;
use dep::bignum::bignum::BigNum;
use dep::bignum::fields::U512::U512;
use dep::poseidon2;
use std::ops::Mul;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul};

// Ed25519 scalar field order (l)
// l = 2^252 + 27742317777372353535851937790883648493
global ED25519_ORDER: Field =
    0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;

/// Computes the Ed25519 scalar field order from its mathematical definition.
/// l = 2^252 + 27742317777372353535851937790883648493
pub fn compute_ed25519_order() -> Field {
    // 2^252 (1 followed by 63 hex zeros = 252 bits)
    let two_pow_252: Field = 0x1000000000000000000000000000000000000000000000000000000000000000;
    // The "small" cofactor: 27742317777372353535851937790883648493
    let cofactor: Field = 0x14def9dea2f79cd65812631a5cf5d3ed;
    two_pow_252 + cofactor
}

// 2^254 as U512 limbs for wide multiplication
// Used in next_witness_wide to combine two hash outputs
// U512 uses [u128; 5] in little-endian order with 120-bit limbs
// 2^254 = 2^(2*120 + 14), so it goes in limb 2 at 2^14 = 16384
global SHIFT_2_254_LIMBS: [u128; 5] = [
    0,     // limb 0 (bits 0-119)
    0,     // limb 1 (bits 120-239)
    16384, // limb 2 (bits 240-359): 2^14
    0,     // limb 3 (bits 360-479)
    0,     // limb 4 (bits 480+)
];

/// Asserts that a field value is a valid Ed25519 scalar field element.
/// i.e. that 0 < value < l (Ed25519 order).
pub fn assert_valid_ed25519_scalar(value: Field) {
    assert(value != 0, "Scalar must be non-zero");
    // Use Noir's built-in lt check for BN254 field elements
    // This constrains value < ED25519_ORDER, i.e., 0 < value < l
    std::field::bn254::assert_lt(value, ED25519_ORDER);
}

/// Derives the next witness value using a single Poseidon2 hash.
///
/// Use this function for SNARK curves where N_SF < N_ed25519 (e.g., BabyJubJub).
/// The result is automatically valid in both the SNARK field and Ed25519's scalar field
/// since any value < N_SF is also < N_ed25519.
///
/// # Arguments
/// * `i` - The update index
/// * `w` - The current witness value
///
/// # Returns
/// The next witness value H(i || w)
pub fn next_witness_native(i: Field, w: Field) -> Field {
    poseidon2::bn254::hash_2([i, w])
}

/// Derives the next witness value using wide Poseidon2 output reduced mod Ed25519 order.
///
/// Use this function for SNARK curves where N_SF > N_ed25519 (e.g., Grumpkin).
/// Combines two Poseidon2 hash outputs (~508 bits) and reduces mod Ed25519 order
/// to produce an unbiased result valid in both fields.
///
/// # Arguments
/// * `i` - The update index
/// * `w` - The current witness value
///
/// # Returns
/// The next witness value: (H(i,w,0) + H(i,w,1) * 2^254) mod l
///
/// # Bias
/// Statistical distance from uniform is ~2^(-254), cryptographically negligible.
///
pub fn next_witness_wide(i: Field, w: Field) -> Field {
    // Two Poseidon2 hashes with domain separation for ~508 bits of entropy
    let h0 = poseidon2::bn254::hash_3([i, w, 0]);
    let h1 = poseidon2::bn254::hash_3([i, w, 1]);

    // Batch all BigNum operations in unconstrained to avoid ACIR/Brillig subgraph warnings.
    // The computation is: result = (h0 + h1 * 2^254) mod ED25519_ORDER
    // Safety: The unconstrained computation is verified by `verify_wide_mod_reduction`
    // which proves the modular reduction equation holds.
    let (result, quotient) = unsafe { compute_wide_mod_with_quotient(h0, h1) };

    // Constrain the result by verifying the modular reduction equation:
    // h0 + h1 * 2^254 = quotient * ED25519_ORDER + result
    // This proves result is the correct remainder, not just any value < ED25519_ORDER.
    verify_wide_mod_reduction(h0, h1, quotient, result);

    result
}

/// Unconstrained helper that computes (h0 + h1 * 2^254) mod ED25519_ORDER
/// and returns both the result and the quotient for verification.
unconstrained fn compute_wide_mod_with_quotient(h0: Field, h1: Field) -> (Field, U512) {
    let h0_wide: U512 = U512::from(h0);
    let h1_wide: U512 = U512::from(h1);
    let shift: U512 = U512::from_limbs(SHIFT_2_254_LIMBS);
    let ed25519_order: U512 = U512::from(ED25519_ORDER);

    let h1_shifted: U512 = h1_wide.mul(shift);
    let wide: U512 = h0_wide + h1_shifted;

    // Get both quotient and remainder using udiv_mod
    let (quotient, reduced): (U512, U512) = wide.udiv_mod(ed25519_order);

    let result: Field = bignum::bignum::to_field(reduced);
    (result, quotient)
}

// Constants for limb-to-Field reconstruction
// U512 uses 120-bit limbs in little-endian order
global TWO_POW_120: Field = 0x1000000000000000000000000000000; // 2^120

/// Converts a Field to U512 limbs in unconstrained code.
unconstrained fn field_to_u512_limbs(f: Field) -> [u128; 5] {
    let u: U512 = U512::from(f);
    u.get_limbs()
}

/// Converts a Field to U512 using unconstrained limb computation + constrained validation.
/// This avoids the internal Brillig validation in U512::from that causes subgraph warnings.
fn field_to_u512_constrained(f: Field) -> U512 {
    // Safety: Limbs are validated by reconstructing the Field and checking equality below.
    let limbs = unsafe { field_to_u512_limbs(f) };
    let u: U512 = U512::from_limbs(limbs);

    // Validate the conversion by reconstructing Field from limbs
    // For BN254 fields (< 2^254), only limbs 0, 1, 2 are used; limbs 3, 4 must be 0
    assert(limbs[3] == 0, "Limb 3 must be 0 for BN254 field");
    assert(limbs[4] == 0, "Limb 4 must be 0 for BN254 field");

    // Reconstruct: f = l0 + l1 * 2^120 + l2 * 2^240
    let l0: Field = limbs[0] as Field;
    let l1: Field = limbs[1] as Field;
    let l2: Field = limbs[2] as Field;
    let reconstructed: Field = l0 + l1 * TWO_POW_120 + l2 * TWO_POW_120 * TWO_POW_120;
    assert(reconstructed == f, "Field to U512 conversion mismatch");

    u
}

/// Constrains that: h0 + h1 * 2^254 = quotient * ED25519_ORDER + result
/// This verifies the modular reduction was computed correctly.
fn verify_wide_mod_reduction(h0: Field, h1: Field, quotient: U512, result: Field) {
    // Convert inputs to U512 using the warning-free conversion
    let h0_wide: U512 = field_to_u512_constrained(h0);
    let h1_wide: U512 = field_to_u512_constrained(h1);
    let shift: U512 = U512::from_limbs(SHIFT_2_254_LIMBS);
    let ed25519_order: U512 = field_to_u512_constrained(ED25519_ORDER);
    let result_wide: U512 = field_to_u512_constrained(result);

    // Compute left side: h0 + h1 * 2^254
    let h1_shifted: U512 = h1_wide.mul(shift);
    let lhs: U512 = h0_wide + h1_shifted;

    // Compute right side: quotient * ED25519_ORDER + result
    let q_times_order: U512 = quotient.mul(ed25519_order);
    let rhs: U512 = q_times_order + result_wide;

    // Verify equality
    assert(lhs == rhs, "Wide mod reduction verification failed");

    // Verify result < ED25519_ORDER (proves it's the canonical remainder)
    std::field::bn254::assert_lt(result, ED25519_ORDER);
}

/// VCOF prove circuit using native (single hash) derivation.
///
/// Use this for SNARK curves where N_SF < N_ed25519 (e.g., BabyJubJub).
/// For Grumpkin, use `vcof_prove_wide` instead.
///
/// Implements VcofProve from the Grease protocol specification. Proves that:
/// 1. The prover knows wn_prev corresponding to pub_prev
/// 2. wn_next was correctly derived via wn_next = H(i || wn_prev)
/// 3. pub_next corresponds to wn_next
///
/// # Public Inputs
/// - `i`: The update index (caller must ensure `i <= u64::MAX`)
/// - `pub_prev`: Public key for the previous witness (wn_prev * G on Grumpkin)
/// - `pub_next`: Public key for the next witness (wn_next * G on Grumpkin)
///
/// # Private Inputs (witnesses)
/// - `wn_prev`: The previous witness value (must be non-zero)
///
/// # Security
/// - Consecutiveness: wn_next is derived deterministically from wn_prev
/// - One-wayness: Cannot derive wn_prev from wn_next (Poseidon2 preimage resistance)
/// - Verifiability: Public keys commit to witness values via discrete log
/// - Zero rejection: Zero witnesses are rejected to prevent identity point attacks
pub fn vcof_prove_native(i: Field, wn_prev: Field, pub_prev: EmbeddedCurvePoint, pub_next: EmbeddedCurvePoint) {
    // Reject zero witness to prevent identity point attacks
    assert(wn_prev != 0, "Previous witness must be non-zero");
    assert(i != 0, "Index must be non-zero");

    // Verify pub_prev = wn_prev * G (proves knowledge of wn_prev)
    let computed_prev = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(wn_prev));
    assert(computed_prev == pub_prev, "pub_prev does not match wn_prev * G");

    // Compute wn_next = H(i || wn_prev) using native single-hash derivation
    let wn_next = next_witness_native(i, wn_prev);

    // Reject zero derived witness (defensive - extremely unlikely from Poseidon2)
    assert(wn_next != 0, "Derived witness must be non-zero");

    // Verify pub_next = wn_next * G
    let computed_next = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(wn_next));
    assert(computed_next == pub_next, "pub_next does not match wn_next * G");
}

/// VCOF prove circuit using wide (double hash + reduction) derivation.
///
/// Use this for SNARK curves where N_SF > N_ed25519 (e.g., Grumpkin).
/// This ensures the derived witness is unbiased and valid in both Ed25519 and the SNARK field.
///
/// Implements VcofProve from the Grease protocol specification. Proves that:
/// 1. The prover knows wn_prev corresponding to pub_prev
/// 2. wn_next was correctly derived via wn_next = (H(i,w,0) + H(i,w,1) * 2^254) mod l
/// 3. pub_next corresponds to wn_next
///
/// # Public Inputs
/// - `i`: The update index (caller must ensure `i <= u64::MAX`)
/// - `pub_prev`: Public key for the previous witness (wn_prev * G on Grumpkin)
/// - `pub_next`: Public key for the next witness (wn_next * G on Grumpkin)
///
/// # Private Inputs (witnesses)
/// - `wn_prev`: The previous witness value (must be valid Ed25519 scalar: 0 < wn_prev < l)
///
/// # Security
/// - Consecutiveness: wn_next is derived deterministically from wn_prev
/// - One-wayness: Cannot derive wn_prev from wn_next (Poseidon2 preimage resistance)
/// - Verifiability: Public keys commit to witness values via discrete log
/// - Zero rejection: Zero witnesses are rejected to prevent identity point attacks
/// - Unbiased: Statistical distance from uniform is ~2^(-254)
/// - Range checked: wn_prev must be a valid Ed25519 scalar
pub fn vcof_prove_wide(i: Field, wn_prev: Field, pub_prev: EmbeddedCurvePoint, pub_next: EmbeddedCurvePoint) {
    // Validate wn_prev is a valid Ed25519 scalar (0 < wn_prev < l)
    // This is critical for Grumpkin where Field can hold values > Ed25519 order
    assert_valid_ed25519_scalar(wn_prev);
    println("wn_prev validated as valid Ed25519 scalar");
    // Reject zero index
    assert(i != 0, "Index must be non-zero");

    // Verify pub_prev = wn_prev * G (proves knowledge of wn_prev)
    let computed_prev = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(wn_prev));
    println(f"P_i = wi.G: {computed_prev}");
    assert(computed_prev == pub_prev, "pub_prev does not match wn_prev * G");

    // Compute wn_next using wide derivation with Ed25519 order reduction
    let wn_next = next_witness_wide(i, wn_prev);

    // Reject zero derived witness (defensive - extremely unlikely from Poseidon2)
    assert(wn_next != 0, "Derived witness must be non-zero");
    println(f"wn_next: {wn_next}");
    // Verify pub_next = wn_next * G
    let computed_next = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(wn_next));
    println(f"P_next = w_next.G: {computed_next}");
    assert(computed_next == pub_next, "pub_next does not match wn_next * G");
}

// ============================================================================
// Tests
// ============================================================================

/// Helper function to compute public key from witness value (w * G)
pub fn witness_to_pubkey(w: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(w))
}

// ============================================================================
// Tests for Ed25519 order constant
// ============================================================================

/// Test: Verify ED25519_ORDER constant matches computed value from definition
/// l = 2^252 + 27742317777372353535851937790883648493
#[test]
fn test_ed25519_order_matches_computed() {
    let computed = compute_ed25519_order();
    assert(computed == ED25519_ORDER, "ED25519_ORDER constant doesn't match computed value");
}

/// Test: Verify ED25519_ORDER hex matches the known decimal representation
/// The decimal value is: 7237005577332262213973186563042994240857116359379907606001950938285454250989
#[test]
fn test_ed25519_order_known_value() {
    // Verify against the well-known hex representation
    let expected: Field = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    assert(ED25519_ORDER == expected, "ED25519_ORDER doesn't match expected hex value");

    // Verify the computed value also matches
    let computed = compute_ed25519_order();
    assert(computed == expected, "Computed Ed25519 order doesn't match expected hex value");
}

// ============================================================================
// Tests for next_witness_native (single hash path)
// ============================================================================

/// Test: Native witness derivation produces consistent results
#[test]
fn test_next_witness_native_deterministic() {
    let i = 1;
    let w: Field = 12345;

    let result1 = next_witness_native(i, w);
    let result2 = next_witness_native(i, w);

    assert(result1 == result2);
}

/// Test: Native witness derivation with different indices produces different results
#[test]
fn test_next_witness_native_different_indices() {
    let w: Field = 12345;

    let result1 = next_witness_native(1, w);
    let result2 = next_witness_native(2, w);

    assert(result1 != result2);
}

/// Test: vcof_prove_native accepts valid inputs
#[test]
fn test_vcof_prove_native_valid_derivation() {
    let i = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_native(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_native(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_native with large index
#[test]
fn test_vcof_prove_native_large_index() {
    let i = 999999;
    let wn_prev: Field = 0xdeadbeef;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_native(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_native(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_native chained updates
#[test]
fn test_vcof_prove_native_chained_updates() {
    let w0: Field = 0xabcdef123456;

    let i1 = 1;
    let pub0 = witness_to_pubkey(w0);
    let w1 = next_witness_native(i1, w0);
    let pub1 = witness_to_pubkey(w1);
    vcof_prove_native(i1, w0, pub0, pub1);

    let i2 = 2;
    let pub1_check = witness_to_pubkey(w1);
    let w2 = next_witness_native(i2, w1);
    let pub2 = witness_to_pubkey(w2);
    vcof_prove_native(i2, w1, pub1_check, pub2);
}

/// Test: vcof_prove_native rejects zero witness
#[test(should_fail)]
fn test_vcof_prove_native_rejects_zero_witness() {
    let i = 1;
    let wn_prev: Field = 0;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_native(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_native(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_native rejects zero index
#[test(should_fail)]
fn test_vcof_prove_native_rejects_zero_index() {
    let i = 0;
    let wn_prev: Field = 0xfeedface;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_native(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_native(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_native rejects wrong pub_next
#[test(should_fail)]
fn test_vcof_prove_native_rejects_wrong_pub_next() {
    let i = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wrong_pub_next = witness_to_pubkey(0xbadbeef);

    vcof_prove_native(i, wn_prev, pub_prev, wrong_pub_next);
}

// ============================================================================
// Tests for next_witness_wide (double hash + reduction path)
// ============================================================================

/// Test: Wide witness derivation produces consistent results
#[test]
fn test_next_witness_wide_deterministic() {
    let i = 1;
    let w: Field = 12345;

    let result1 = next_witness_wide(i, w);
    let result2 = next_witness_wide(i, w);

    assert(result1 == result2);
}

/// Test: Wide witness derivation with different indices produces different results
#[test]
fn test_next_witness_wide_different_indices() {
    let w: Field = 12345;

    let result1 = next_witness_wide(1, w);
    let result2 = next_witness_wide(2, w);

    assert(result1 != result2);
}

/// Test: Wide witness derivation produces value less than Ed25519 order
#[test]
fn test_next_witness_wide_within_ed25519_order() {
    let i = 1;
    let w: Field = 0xdeadbeef;

    let result = next_witness_wide(i, w);

    // Result should be < ED25519_ORDER (verified by assert_lt in next_witness_wide)
    // Also verify it's non-zero
    assert(result != 0);
}

/// Test: vcof_prove_wide accepts valid inputs
#[test]
fn test_vcof_prove_wide_valid_derivation() {
    let i = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_wide with large index
#[test]
fn test_vcof_prove_wide_large_index() {
    let i = 999999;
    let wn_prev: Field = 0xdeadbeef;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_wide chained updates
#[test]
fn test_vcof_prove_wide_chained_updates() {
    let w0: Field = 0xabcdef123456;

    let i1 = 1;
    let pub0 = witness_to_pubkey(w0);
    let w1 = next_witness_wide(i1, w0);
    let pub1 = witness_to_pubkey(w1);
    vcof_prove_wide(i1, w0, pub0, pub1);

    let i2 = 2;
    let pub1_check = witness_to_pubkey(w1);
    let w2 = next_witness_wide(i2, w1);
    let pub2 = witness_to_pubkey(w2);
    vcof_prove_wide(i2, w1, pub1_check, pub2);

    let i3 = 3;
    let pub2_check = witness_to_pubkey(w2);
    let w3 = next_witness_wide(i3, w2);
    let pub3 = witness_to_pubkey(w3);
    vcof_prove_wide(i3, w2, pub2_check, pub3);
}

/// Test: vcof_prove_wide rejects zero witness
#[test(should_fail)]
fn test_vcof_prove_wide_rejects_zero_witness() {
    let i = 1;
    let wn_prev: Field = 0;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_wide rejects zero index
#[test(should_fail)]
fn test_vcof_prove_wide_rejects_zero_index() {
    let i = 0;
    let wn_prev: Field = 0xfeedface;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_wide rejects wrong pub_next
#[test(should_fail)]
fn test_vcof_prove_wide_rejects_wrong_pub_next() {
    let i = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wrong_pub_next = witness_to_pubkey(0xbadbeef);

    vcof_prove_wide(i, wn_prev, pub_prev, wrong_pub_next);
}

/// Test: vcof_prove_wide rejects swapped pubkeys
#[test(should_fail)]
fn test_vcof_prove_wide_rejects_swapped_pubkeys() {
    let i = 1;
    let wn_prev: Field = 12345;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_next, pub_prev);
}

/// Test: vcof_prove_wide rejects witness >= Ed25519 order
#[test(should_fail)]
fn test_vcof_prove_wide_rejects_witness_above_ed25519_order() {
    let i = 1;
    // ED25519_ORDER is the maximum valid value + 1, so using it should fail
    let wn_prev: Field = ED25519_ORDER;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

/// Test: vcof_prove_wide accepts witness at Ed25519 order - 1
#[test]
fn test_vcof_prove_wide_accepts_max_valid_witness() {
    let i = 1;
    // ED25519_ORDER - 1 is the maximum valid scalar
    let wn_prev: Field = ED25519_ORDER - 1;

    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    vcof_prove_wide(i, wn_prev, pub_prev, pub_next);
}

// ============================================================================
// Tests verifying native and wide produce different results
// ============================================================================

/// Test: Native and wide derivations produce different results (as expected)
/// This confirms the two paths are distinct implementations.
#[test]
fn test_native_and_wide_produce_different_results() {
    let i = 1;
    let w: Field = 12345;

    let native_result = next_witness_native(i, w);
    let wide_result = next_witness_wide(i, w);

    // They should be different because:
    // - native: H(i || w)
    // - wide: (H(i,w,0) + H(i,w,1) * 2^254) mod l
    assert(native_result != wide_result);
}

// ============================================================================
// Test Vector Generation
// ============================================================================

/// Generates a single test vector using native derivation (for BabyJubJub-like curves).
fn generate_single_vector_native(i: Field, wn_prev: Field) {
    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_native(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    let pub_prev_x = pub_prev.x;
    let pub_prev_y = pub_prev.y;
    let pub_next_x = pub_next.x;
    let pub_next_y = pub_next.y;

    println(f"VECTOR|0|{i}");
    println(f"VECTOR|1|{wn_prev}");
    println(f"VECTOR|2|{wn_next}");
    println(f"VECTOR|3|{pub_prev_x}");
    println(f"VECTOR|4|{pub_prev_y}");
    println(f"VECTOR|5|{pub_next_x}");
    println(f"VECTOR|6|{pub_next_y}");
    println("VECTOR|END");
}

/// Generates a single test vector using wide derivation (for Grumpkin-like curves).
fn generate_single_vector_wide(i: Field, wn_prev: Field) {
    let pub_prev = witness_to_pubkey(wn_prev);
    let wn_next = next_witness_wide(i, wn_prev);
    let pub_next = witness_to_pubkey(wn_next);

    let pub_prev_x = pub_prev.x;
    let pub_prev_y = pub_prev.y;
    let pub_next_x = pub_next.x;
    let pub_next_y = pub_next.y;

    println(f"VECTOR|0|{i}");
    println(f"VECTOR|1|{wn_prev}");
    println(f"VECTOR|2|{wn_next}");
    println(f"VECTOR|3|{pub_prev_x}");
    println(f"VECTOR|4|{pub_prev_y}");
    println(f"VECTOR|5|{pub_next_x}");
    println(f"VECTOR|6|{pub_next_y}");
    println("VECTOR|END");
}

/// VECTOR GENERATOR - Native derivation for BabyJubJub-like curves (N_SF < N_ed25519)
/// Run with: nargo test generate_test_vectors_native --show-output
#[test]
fn generate_test_vectors_native() {
    println("=== BEGIN TEST VECTORS (NATIVE - BabyJubJub) ===");
    println("HEADER,i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y");

    let seeds: [Field; 10] = [
        0x12345,
        0xdeadbeef,
        0xfeedface,
        0xabcdef123456,
        0x1,
        0xffffffff,
        0x123456789abcdef,
        0x9999999999,
        0x2523648240000001ba344d80000000086121000000000013a700000000000012,
        0x42424242,
    ];

    for seed in seeds {
        generate_single_vector_native(1, seed);
    }

    for seed in seeds {
        generate_single_vector_native(420, seed);
    }

    println("=== END TEST VECTORS (NATIVE) ===");
}

/// VECTOR GENERATOR - Wide derivation for Grumpkin-like curves (N_SF > N_ed25519)
/// Run with: nargo test generate_test_vectors_wide --show-output
#[test]
fn generate_test_vectors_wide() {
    println("=== BEGIN TEST VECTORS (WIDE - Grumpkin) ===");
    println("HEADER,i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y");

    let seeds: [Field; 10] = [
        0x12345,
        0xdeadbeef,
        0xfeedface,
        0xabcdef123456,
        0x1,
        0xffffffff,
        0x123456789abcdef,
        0x9999999999,
        0x2523648240000001ba344d80000000086121000000000013a700000000000012,
        0x42424242,
    ];

    for seed in seeds {
        generate_single_vector_wide(1, seed);
    }

    for seed in seeds {
        generate_single_vector_wide(420, seed);
    }

    println("=== END TEST VECTORS (WIDE) ===");
}

/// VECTOR GENERATOR - Chain test vectors using native derivation (BabyJubJub)
#[test]
fn generate_chain_test_vectors_native() {
    println("=== BEGIN CHAIN TEST VECTORS (NATIVE - BabyJubJub) ===");
    println("HEADER,i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y");

    let mut w: Field = 0xabcdef123456789;

    for i in 1..11 {
        generate_single_vector_native(i as Field, w);
        w = next_witness_native(i as Field, w);
    }

    println("=== END CHAIN TEST VECTORS (NATIVE) ===");
}

/// VECTOR GENERATOR - Chain test vectors using wide derivation (Grumpkin)
#[test]
fn generate_chain_test_vectors_wide() {
    println("=== BEGIN CHAIN TEST VECTORS (WIDE - Grumpkin) ===");
    println("HEADER,i,wn_prev,wn_next,pub_prev_x,pub_prev_y,pub_next_x,pub_next_y");

    let mut w: Field = 0xabcdef123456789;

    for i in 1..11 {
        generate_single_vector_wide(i as Field, w);
        w = next_witness_wide(i as Field, w);
    }

    println("=== END CHAIN TEST VECTORS (WIDE) ===");
}
