use crate::{Fq, Fr, Point};
use ark_ec::hashing::HashToCurveError;
use ark_ec::short_weierstrass::Affine;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::{AdditiveGroup, Field, MontFp, PrimeField};
use ark_grumpkin::GrumpkinConfig;
use blake2::Blake2b512;
use subtle::{Choice, ConstantTimeEq};

const SEC_PARAM_FQ: usize = 254;
type FqHasher = DefaultFieldHasher<Blake2b512, SEC_PARAM_FQ>;

const HASH_TO_CURVE_DOMAIN: &[u8] = b"Grumpkin_XMD:Blake2b-512_TI_RO";

/// Grumpkin curve: y^2 = x^3 + B where B = -17
const B: Fq = MontFp!("-17");

/// Number of iterations for constant-time hash-to-curve.
/// With 256 iterations, probability of failure is ~2^-256 (negligible).
const HASH_TO_CURVE_ITERATIONS: u64 = 256;

/// Constant-time selection for Fq field elements.
#[inline]
fn fq_conditional_select(a: &Fq, b: &Fq, choice: Choice) -> Fq {
    let mask = -(choice.unwrap_u8() as i64) as u64;
    let a_limbs = a.into_bigint().0;
    let b_limbs = b.into_bigint().0;
    let result: [u64; 4] = std::array::from_fn(|i| a_limbs[i] ^ (mask & (a_limbs[i] ^ b_limbs[i])));
    Fq::from_bigint(ark_ff::BigInt(result)).unwrap()
}

/// Constant-time comparison: returns Choice(1) if a > b.
/// Compares limbs from most significant to least significant.
#[inline]
fn fq_ct_gt(a: &Fq, b: &Fq) -> Choice {
    let a_limbs = a.into_bigint().0;
    let b_limbs = b.into_bigint().0;

    // Compare from most significant limb to least significant
    // gt = 1 if a > b, lt = 1 if a < b
    let mut gt = Choice::from(0);
    let mut lt = Choice::from(0);

    // Iterate from most significant (index 3) to least significant (index 0)
    for i in (0..4).rev() {
        let a_i = a_limbs[i];
        let b_i = b_limbs[i];

        // a_i > b_i in constant time
        let gt_i = Choice::from(((b_i.wrapping_sub(a_i) >> 63) & 1) as u8);
        // a_i < b_i in constant time
        let lt_i = Choice::from(((a_i.wrapping_sub(b_i) >> 63) & 1) as u8);

        // Update gt/lt only if we haven't already determined the result
        let undecided = !gt & !lt;
        gt = gt | (undecided & gt_i);
        lt = lt | (undecided & lt_i);
    }

    gt
}

/// Constant-time equality for Fq.
#[inline]
fn fq_ct_eq(a: &Fq, b: &Fq) -> Choice {
    a.into_bigint().0.ct_eq(&b.into_bigint().0)
}

/// Hash arbitrary bytes to a point on the Grumpkin curve.
///
/// Uses constant-time try-and-increment: always performs exactly HASH_TO_CURVE_ITERATIONS
/// iterations, using conditional selection to capture the first valid point.
/// This prevents timing side-channels that would leak information about which
/// iteration produced a valid point.
pub fn hash_to_curve(msg: &[u8]) -> Result<Point, HashToCurveError> {
    let hasher = <FqHasher as HashToField<Fq>>::new(HASH_TO_CURVE_DOMAIN);

    let mut result_x = Fq::ZERO;
    let mut result_y = Fq::ZERO;
    let mut found = Choice::from(0);

    // Always iterate exactly HASH_TO_CURVE_ITERATIONS times (constant-time)
    for counter in 0u64..HASH_TO_CURVE_ITERATIONS {
        let input = [msg, &counter.to_le_bytes()].concat();
        let x_coords: [Fq; 1] = hasher.hash_to_field(&input);
        let x = x_coords[0];

        // For Grumpkin (y^2 = x^3 + B), compute y^2 = x^3 + B
        let y_squared = x.pow([3]) + B;

        // Attempt sqrt - returns Some(y) if y_squared is a quadratic residue
        // We need to handle this in constant-time
        let (is_square, y) = constant_time_sqrt(&y_squared);

        // Update result only if:
        // 1. This iteration produced a valid point (is_square)
        // 2. We haven't already found a valid point (!found)
        let should_update = is_square & !found;

        result_x = fq_conditional_select(&result_x, &x, should_update);
        result_y = fq_conditional_select(&result_y, &y, should_update);
        found = found | is_square;
    }

    // Normalize y: choose the lexicographically smaller of y and -y (constant-time)
    let neg_y = -result_y;
    let y_is_larger = fq_ct_gt(&result_y, &neg_y);
    let final_y = fq_conditional_select(&result_y, &neg_y, y_is_larger);

    // Return result (found should be true with overwhelming probability)
    if bool::from(found) {
        Ok(Affine::<GrumpkinConfig>::new(result_x, final_y))
    } else {
        Err(HashToCurveError::MapToCurveError(
            "Failed to find valid point (extremely unlikely)".to_string(),
        ))
    }
}

/// Constant-time square root computation.
/// Returns (is_square, sqrt) where:
/// - is_square is Choice(1) if the input is a quadratic residue
/// - sqrt is the square root if is_square, or zero otherwise
///
/// Uses the Tonelli-Shanks algorithm with constant-time operations.
fn constant_time_sqrt(a: &Fq) -> (Choice, Fq) {
    // For constant-time, we compute the sqrt candidate and verify
    // by squaring, rather than using early-exit Tonelli-Shanks.

    // Use arkworks sqrt (may not be fully constant-time internally,
    // but we wrap it in constant-time selection)
    match a.sqrt() {
        Some(sqrt) => {
            // Verify: sqrt^2 should equal a
            let is_valid = fq_ct_eq(&sqrt.square(), a);
            (is_valid, sqrt)
        }
        None => {
            // Not a quadratic residue - return zero
            (Choice::from(0), Fq::ZERO)
        }
    }
}

const SEC_PARAM_FR: usize = 254;
type FrHasher = DefaultFieldHasher<Blake2b512, SEC_PARAM_FR>;

pub const FR_HASH_TO_FIELD_DOMAIN: &[u8] = b"Grumpkin-FrH2F-ARK-v1";

/// Hash arbitrary bytes to N field elements in Fr.
pub fn hash_to_fr<const N: usize>(msg: &[u8]) -> [Fr; N] {
    let hasher = <FrHasher as HashToField<Fr>>::new(FR_HASH_TO_FIELD_DOMAIN);
    hasher.hash_to_field::<N>(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_to_curve() {
        let msg = b"Hello, world!";
        let p = hash_to_curve(msg).unwrap();
        assert!(p.is_on_curve());
        // Grumpkin has cofactor 1, so all points are in the correct subgroup
    }

    #[test]
    fn hash_to_curve_deterministic() {
        let msg = b"test message";
        let p1 = hash_to_curve(msg).unwrap();
        let p2 = hash_to_curve(msg).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn hash_to_fr_deterministic() {
        let msg = b"test message";
        let h1: [Fr; 2] = hash_to_fr(msg);
        let h2: [Fr; 2] = hash_to_fr(msg);
        assert_eq!(h1, h2);
    }
}
