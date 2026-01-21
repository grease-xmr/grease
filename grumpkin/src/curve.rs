use crate::{Fq, Fr, Point};
use ark_ec::hashing::HashToCurveError;
use ark_ec::short_weierstrass::Affine;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::{Field, MontFp};
use ark_grumpkin::GrumpkinConfig;
use blake2::Blake2b512;

const SEC_PARAM_FQ: usize = 254;
type FqHasher = DefaultFieldHasher<Blake2b512, SEC_PARAM_FQ>;

const HASH_TO_CURVE_DOMAIN: &[u8] = b"Grumpkin_XMD:Blake2b-512_TI_RO";

/// Grumpkin curve: y^2 = x^3 + B where B = -17
const B: Fq = MontFp!("-17");

/// Hash arbitrary bytes to a point on the Grumpkin curve using try-and-increment.
pub fn hash_to_curve(msg: &[u8]) -> Result<Point, HashToCurveError> {
    let hasher = <FqHasher as HashToField<Fq>>::new(HASH_TO_CURVE_DOMAIN);

    for counter in 0u64.. {
        let input = [msg, &counter.to_le_bytes()].concat();
        let x: [Fq; 1] = hasher.hash_to_field(&input);
        let x = x[0];

        // Grumpkin: y² = x³ + B
        let y_squared = x * x * x + B;

        if let Some(y) = y_squared.sqrt() {
            // Normalize: choose the lexicographically smaller of y and -y
            let neg_y = -y;
            let final_y = if y < neg_y { y } else { neg_y };
            return Ok(Affine::<GrumpkinConfig>::new(x, final_y));
        }
    }

    Err(HashToCurveError::MapToCurveError("Failed to find valid point".to_string()))
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
    fn hash_to_curve_on_curve() {
        let msg = b"Hello, world!";
        let p = hash_to_curve(msg).unwrap();
        assert!(p.is_on_curve());
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
