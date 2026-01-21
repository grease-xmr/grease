//! Implements traits to make Grumpkin scalars compatible with Serai's `CipherSuite`

use crate::Fr;
use crate::constants::*;
use ark_ff::{AdditiveGroup, BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::RngCore;
use group::ff::helpers::sqrt_ratio_generic;
use group::ff::{Field as SeraiField, FieldBits, PrimeField as SeraiPrimeField, PrimeFieldBits};
use num_bigint::BigUint;
use std::io::Cursor;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Default, Clone, Copy, Zeroize, PartialEq, Eq)]
pub struct Scalar(pub Fr);

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self(Fr::from(value))
    }
}

impl From<BigUint> for Scalar {
    fn from(value: BigUint) -> Self {
        Self(Fr::from(value))
    }
}

impl From<&BigUint> for Scalar {
    fn from(value: &BigUint) -> Self {
        Self(Fr::from(value.clone()))
    }
}

impl From<Scalar> for BigUint {
    fn from(value: Scalar) -> Self {
        value.0.into()
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.into_bigint().0.ct_eq(&other.0.into_bigint().0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut a_bigint = Zeroizing::new(a.0.into_bigint());
        let mut b_bigint = Zeroizing::new(b.0.into_bigint());
        let result: [u64; 4] = std::array::from_fn(|i| u64::conditional_select(&a_bigint.0[i], &b_bigint.0[i], choice));
        a_bigint.zeroize();
        b_bigint.zeroize();
        Self(Fr::from_bigint(ark_ff::BigInt(result)).unwrap())
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.0.neg().into()
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.0.add(rhs.0).into()
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.0.add(&rhs.0).into()
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.sub(rhs.0).into()
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.0.sub(&rhs.0).into()
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.0.mul(rhs.0).into()
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.0.mul(&rhs.0).into()
    }
}

impl Sum for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.fold(Fr::zero(), |acc, x| acc + x.0);
        Scalar(sum)
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let sum = iter.fold(Fr::zero(), |acc, x| acc + x.0);
        Scalar(sum)
    }
}

impl Product for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let prod = iter.fold(Fr::one(), |acc, x| acc * x.0);
        Scalar(prod)
    }
}

impl<'a> Product<&'a Self> for Scalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let prod = iter.fold(Fr::one(), |acc, x| acc * x.0);
        Scalar(prod)
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.0 = self.0 * rhs.0;
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Self) {
        self.0 = self.0 * rhs.0;
    }
}

impl SeraiPrimeField for Scalar {
    type Repr = [u8; SCALAR_SIZE];

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        // Use deserialize_compressed which properly rejects non-canonical values (>= modulus)
        let reader = Cursor::new(&repr[..]);
        match Fr::deserialize_compressed(reader) {
            Ok(f) => CtOption::new(Self(f), Choice::from(1)),
            Err(_) => CtOption::new(Self::ZERO, Choice::from(0)),
        }
    }

    fn to_repr(&self) -> Self::Repr {
        let mut bytes = Self::Repr::default();
        let mut writer = Cursor::new(&mut bytes[..]);
        self.0.serialize_uncompressed(&mut writer).expect("Serialization failed");
        bytes
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.to_repr()[0] & 1)
    }

    const MODULUS: &'static str = MODULUS_STR_FR;
    const NUM_BITS: u32 = 254;
    const CAPACITY: u32 = 253;
    const TWO_INV: Self = Self(INV_2);
    const MULTIPLICATIVE_GENERATOR: Self = Self(Fr::GENERATOR);
    const S: u32 = 1;
    const ROOT_OF_UNITY: Self = Self(ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Self(ROOT_OF_UNITY_INV);
    const DELTA: Self = Self(DELTA);
}

impl From<Fr> for Scalar {
    fn from(value: Fr) -> Self {
        Self(value)
    }
}

impl SeraiField for Scalar {
    const ZERO: Self = Self(Fr::ZERO);
    const ONE: Self = Self(Fr::ONE);

    fn random(mut rng: impl RngCore) -> Self {
        let inner = Fr::rand(&mut rng);
        inner.into()
    }

    fn square(&self) -> Self {
        self.0.square().into()
    }

    fn double(&self) -> Self {
        self.0.double().into()
    }

    fn invert(&self) -> CtOption<Self> {
        match self.0.inverse() {
            Some(inv) => CtOption::new(Self(inv), Choice::from(1)),
            None => CtOption::new(Self(Fr::ZERO), Choice::from(0)),
        }
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        sqrt_ratio_generic(num, div)
    }

    fn sqrt(&self) -> CtOption<Self> {
        match self.0.sqrt() {
            Some(sqrt) => CtOption::new(Self(sqrt), Choice::from(1)),
            None => CtOption::new(Self(Fr::ZERO), Choice::from(0)),
        }
    }

    fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        self.0.pow(exp.as_ref()).into()
    }
}

impl PrimeFieldBits for Scalar {
    type ReprBits = [u8; 32];

    fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        self.to_repr().into()
    }

    fn char_le_bits() -> FieldBits<Self::ReprBits> {
        let mut bits = Self::ReprBits::default();
        let modulus = Fr::MODULUS;
        bits.copy_from_slice(&modulus.to_bytes_le());
        bits.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::MODULUS_STR_FR;
    use crate::{GrumpkinPoint, Scalar};
    use elliptic_curve::Field;
    use group::ff::PrimeField;
    use num_bigint::BigUint;
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

    #[test]
    fn serai_group_tests() {
        let mut rng = ark_std::test_rng();
        ff_group_tests::group::test_group::<_, GrumpkinPoint>(&mut rng);
    }

    #[test]
    fn serai_scalar_tests() {
        let mut rng = ark_std::test_rng();
        ff_group_tests::prime_field::test_prime_field_bits::<_, Scalar>(&mut rng);
    }

    #[test]
    fn repr_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let k = Scalar::random(&mut rng);
            let bytes = k.to_repr();
            let k2 = Scalar::from_repr(bytes).unwrap();
            assert_eq!(k, k2);
        }
    }

    #[test]
    fn from_repr_rejects_non_canonical() {
        // The modulus is 21888242871839275222246405745257275088696311157297823662689037894645226208583
        // Test with modulus itself (should be rejected)
        let modulus_bytes: [u8; 32] = [
            0x47, 0xFD, 0x7C, 0xD8, 0x16, 0x8C, 0x20, 0x3C, 0x8D, 0xCA, 0x71, 0x68, 0x91, 0x6A, 0x81, 0x97, 0x5D, 0x58,
            0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8, 0x29, 0xA0, 0x31, 0xE1, 0x72, 0x4E, 0x64, 0x30,
        ];
        assert!(bool::from(Scalar::from_repr(modulus_bytes).is_none()));

        // Test with modulus + 1 (should be rejected)
        let modulus_plus_one: [u8; 32] = [
            0x48, 0xFD, 0x7C, 0xD8, 0x16, 0x8C, 0x20, 0x3C, 0x8D, 0xCA, 0x71, 0x68, 0x91, 0x6A, 0x81, 0x97, 0x5D, 0x58,
            0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8, 0x29, 0xA0, 0x31, 0xE1, 0x72, 0x4E, 0x64, 0x30,
        ];
        assert!(bool::from(Scalar::from_repr(modulus_plus_one).is_none()));

        // Test with all 0xFF bytes (should be rejected)
        let max_bytes: [u8; 32] = [0xFF; 32];
        assert!(bool::from(Scalar::from_repr(max_bytes).is_none()));

        // Test with modulus - 1 (should be accepted)
        let modulus_minus_one: [u8; 32] = [
            0x46, 0xFD, 0x7C, 0xD8, 0x16, 0x8C, 0x20, 0x3C, 0x8D, 0xCA, 0x71, 0x68, 0x91, 0x6A, 0x81, 0x97, 0x5D, 0x58,
            0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8, 0x29, 0xA0, 0x31, 0xE1, 0x72, 0x4E, 0x64, 0x30,
        ];
        assert!(bool::from(Scalar::from_repr(modulus_minus_one).is_some()));

        // Test with zero (should be accepted)
        let zero_bytes: [u8; 32] = [0u8; 32];
        assert!(bool::from(Scalar::from_repr(zero_bytes).is_some()));
    }

    // ==================== From/Into conversion tests ====================

    #[test]
    fn from_u64() {
        let s = Scalar::from(42u64);
        assert_eq!(s, Scalar::from(42u64));

        let zero = Scalar::from(0u64);
        assert_eq!(zero, Scalar::ZERO);

        let one = Scalar::from(1u64);
        assert_eq!(one, Scalar::ONE);
    }

    #[test]
    fn from_biguint() {
        let val = BigUint::from(12345u64);
        let s = Scalar::from(val.clone());
        let s_ref = Scalar::from(&val);
        assert_eq!(s, s_ref);

        // Roundtrip
        let back: BigUint = s.into();
        assert_eq!(back, val);
    }

    #[test]
    fn biguint_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let s = Scalar::random(&mut rng);
            let big: BigUint = s.into();
            let s2 = Scalar::from(big);
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn from_fr() {
        use crate::Fr;
        use ark_ff::One;

        let fr = Fr::one();
        let s: Scalar = fr.into();
        assert_eq!(s, Scalar::ONE);
    }

    // ==================== ConstantTimeEq tests ====================

    #[test]
    fn constant_time_eq() {
        let a = Scalar::from(42u64);
        let b = Scalar::from(42u64);
        let c = Scalar::from(43u64);

        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
        assert!(bool::from(Scalar::ZERO.ct_eq(&Scalar::ZERO)));
        assert!(bool::from(Scalar::ONE.ct_eq(&Scalar::ONE)));
    }

    // ==================== ConditionallySelectable tests ====================

    #[test]
    fn conditional_select() {
        let a = Scalar::from(100u64);
        let b = Scalar::from(200u64);

        // choice = 0 should select a
        let result_a = Scalar::conditional_select(&a, &b, Choice::from(0));
        assert_eq!(result_a, a);

        // choice = 1 should select b
        let result_b = Scalar::conditional_select(&a, &b, Choice::from(1));
        assert_eq!(result_b, b);
    }

    #[test]
    fn conditional_select_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let a = Scalar::random(&mut rng);
            let b = Scalar::random(&mut rng);

            let sel_a = Scalar::conditional_select(&a, &b, Choice::from(0));
            let sel_b = Scalar::conditional_select(&a, &b, Choice::from(1));

            assert_eq!(sel_a, a);
            assert_eq!(sel_b, b);
        }
    }

    // ==================== Arithmetic operator tests ====================

    #[test]
    fn neg() {
        let a = Scalar::from(42u64);
        let neg_a = -a;
        assert_eq!(a + neg_a, Scalar::ZERO);
        assert_eq!(-Scalar::ZERO, Scalar::ZERO);
        assert_eq!(-(-a), a);
    }

    #[test]
    fn add_variants() {
        let a = Scalar::from(10u64);
        let b = Scalar::from(20u64);

        // Add owned
        assert_eq!(a + b, Scalar::from(30u64));

        // Add reference
        assert_eq!(a + &b, Scalar::from(30u64));
    }

    #[test]
    fn sub_variants() {
        let a = Scalar::from(30u64);
        let b = Scalar::from(10u64);

        // Sub owned
        assert_eq!(a - b, Scalar::from(20u64));

        // Sub reference
        assert_eq!(a - &b, Scalar::from(20u64));
    }

    #[test]
    fn mul_variants() {
        let a = Scalar::from(5u64);
        let b = Scalar::from(7u64);

        // Mul owned
        assert_eq!(a * b, Scalar::from(35u64));

        // Mul reference
        assert_eq!(a * &b, Scalar::from(35u64));
    }

    #[test]
    fn add_assign_variants() {
        let mut a = Scalar::from(10u64);
        let b = Scalar::from(5u64);

        a += b;
        assert_eq!(a, Scalar::from(15u64));

        a += &b;
        assert_eq!(a, Scalar::from(20u64));
    }

    #[test]
    fn sub_assign_variants() {
        let mut a = Scalar::from(20u64);
        let b = Scalar::from(5u64);

        a -= b;
        assert_eq!(a, Scalar::from(15u64));

        a -= &b;
        assert_eq!(a, Scalar::from(10u64));
    }

    #[test]
    fn mul_assign_variants() {
        let mut a = Scalar::from(3u64);
        let b = Scalar::from(4u64);

        a *= b;
        assert_eq!(a, Scalar::from(12u64));

        a *= &b;
        assert_eq!(a, Scalar::from(48u64));
    }

    #[test]
    fn sum_owned() {
        let scalars = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let sum: Scalar = scalars.into_iter().sum();
        assert_eq!(sum, Scalar::from(6u64));

        // Empty sum should be zero
        let empty: Vec<Scalar> = vec![];
        let empty_sum: Scalar = empty.into_iter().sum();
        assert_eq!(empty_sum, Scalar::ZERO);
    }

    #[test]
    fn sum_refs() {
        let scalars = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let sum: Scalar = scalars.iter().sum();
        assert_eq!(sum, Scalar::from(6u64));
    }

    #[test]
    fn product_owned() {
        let scalars = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let prod: Scalar = scalars.into_iter().product();
        assert_eq!(prod, Scalar::from(24u64));

        // Empty product should be one
        let empty: Vec<Scalar> = vec![];
        let empty_prod: Scalar = empty.into_iter().product();
        assert_eq!(empty_prod, Scalar::ONE);
    }

    #[test]
    fn product_refs() {
        let scalars = vec![Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let prod: Scalar = scalars.iter().product();
        assert_eq!(prod, Scalar::from(24u64));
    }

    // ==================== Field operation tests ====================

    #[test]
    fn square() {
        let a = Scalar::from(7u64);
        assert_eq!(a.square(), Scalar::from(49u64));
        assert_eq!(Scalar::ZERO.square(), Scalar::ZERO);
        assert_eq!(Scalar::ONE.square(), Scalar::ONE);
    }

    #[test]
    fn double() {
        let a = Scalar::from(21u64);
        assert_eq!(a.double(), Scalar::from(42u64));
        assert_eq!(Scalar::ZERO.double(), Scalar::ZERO);
    }

    #[test]
    fn invert() {
        let a = Scalar::from(7u64);
        let a_inv = a.invert().unwrap();
        assert_eq!(a * a_inv, Scalar::ONE);

        // Zero has no inverse
        assert!(bool::from(Scalar::ZERO.invert().is_none()));

        // One is its own inverse
        assert_eq!(Scalar::ONE.invert().unwrap(), Scalar::ONE);
    }

    #[test]
    fn invert_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let a = Scalar::random(&mut rng);
            if a != Scalar::ZERO {
                let a_inv = a.invert().unwrap();
                assert_eq!(a * a_inv, Scalar::ONE);
            }
        }
    }

    #[test]
    fn sqrt() {
        // 4 is a quadratic residue, sqrt(4) = 2 or -2
        let four = Scalar::from(4u64);
        let sqrt_four = four.sqrt().unwrap();
        assert_eq!(sqrt_four.square(), four);

        // 9 is a quadratic residue
        let nine = Scalar::from(9u64);
        let sqrt_nine = nine.sqrt().unwrap();
        assert_eq!(sqrt_nine.square(), nine);

        // Zero
        assert_eq!(Scalar::ZERO.sqrt().unwrap(), Scalar::ZERO);

        // One
        assert_eq!(Scalar::ONE.sqrt().unwrap().square(), Scalar::ONE);
    }

    #[test]
    fn sqrt_ratio() {
        use group::ff::Field as SeraiField;

        let num = Scalar::from(16u64);
        let div = Scalar::from(4u64);
        let (is_square, result) = Scalar::sqrt_ratio(&num, &div);

        // 16/4 = 4, sqrt(4) = 2 or -2
        assert!(bool::from(is_square));
        assert_eq!(result.square() * div, num);
    }

    #[test]
    fn pow_vartime() {
        use group::ff::Field as SeraiField;

        let base = Scalar::from(2u64);

        // 2^0 = 1
        assert_eq!(base.pow_vartime([0u64]), Scalar::ONE);

        // 2^1 = 2
        assert_eq!(base.pow_vartime([1u64]), base);

        // 2^10 = 1024
        assert_eq!(base.pow_vartime([10u64]), Scalar::from(1024u64));

        // x^0 = 1 for any x
        let mut rng = ark_std::test_rng();
        let x = Scalar::random(&mut rng);
        assert_eq!(x.pow_vartime([0u64]), Scalar::ONE);
    }

    // ==================== PrimeField constant tests ====================

    #[test]
    fn primefield_constants() {
        // MODULUS string should match expected
        assert_eq!(Scalar::MODULUS, MODULUS_STR_FR);

        // NUM_BITS should be 254 for Grumpkin scalar field
        assert_eq!(Scalar::NUM_BITS, 254);

        // CAPACITY should be NUM_BITS - 1
        assert_eq!(Scalar::CAPACITY, 253);

        // S should be 1 (q-1 = 2^1 * t)
        assert_eq!(Scalar::S, 1);
    }

    #[test]
    fn primefield_two_inv() {
        // TWO_INV * 2 should equal 1
        let two = Scalar::from(2u64);
        assert_eq!(Scalar::TWO_INV * two, Scalar::ONE);
    }

    #[test]
    fn primefield_root_of_unity() {
        use group::ff::Field as SeraiField;

        // ROOT_OF_UNITY^(2^S) should equal 1
        let root = Scalar::ROOT_OF_UNITY;
        let two_pow_s = 1u64 << Scalar::S;
        assert_eq!(root.pow_vartime([two_pow_s]), Scalar::ONE);

        // ROOT_OF_UNITY * ROOT_OF_UNITY_INV should equal 1
        assert_eq!(root * Scalar::ROOT_OF_UNITY_INV, Scalar::ONE);
    }

    #[test]
    fn primefield_multiplicative_generator() {
        // Generator should not be zero or one
        assert_ne!(Scalar::MULTIPLICATIVE_GENERATOR, Scalar::ZERO);
        assert_ne!(Scalar::MULTIPLICATIVE_GENERATOR, Scalar::ONE);
    }

    #[test]
    fn primefield_delta() {
        use group::ff::Field as SeraiField;

        // DELTA = MULTIPLICATIVE_GENERATOR^(2^S)
        let two_pow_s = 1u64 << Scalar::S;
        let expected_delta = Scalar::MULTIPLICATIVE_GENERATOR.pow_vartime([two_pow_s]);
        assert_eq!(Scalar::DELTA, expected_delta);
    }

    #[test]
    fn is_odd() {
        // 0 is even
        assert!(!bool::from(Scalar::ZERO.is_odd()));

        // 1 is odd
        assert!(bool::from(Scalar::ONE.is_odd()));

        // 2 is even
        assert!(!bool::from(Scalar::from(2u64).is_odd()));

        // 3 is odd
        assert!(bool::from(Scalar::from(3u64).is_odd()));
    }

    // ==================== Zeroize test ====================

    #[test]
    fn zeroize() {
        use zeroize::Zeroize;

        let mut s = Scalar::from(12345u64);
        s.zeroize();
        assert_eq!(s, Scalar::ZERO);
    }
}
