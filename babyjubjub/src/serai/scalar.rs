//! Implements traits to make BabyJubJub compatible with Serai's `CipherSuite`

use crate::{BjjConfig, Fr, constants::*};
use ark_ec::CurveConfig;
use ark_ff::{AdditiveGroup, BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
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
pub struct Scalar(pub <BjjConfig as CurveConfig>::ScalarField);

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
        // Use the bit value directly without branching
        let mask = -(choice.unwrap_u8() as i64) as u64;
        let mut a_bigint = Zeroizing::new(a.0.into_bigint());
        let mut b_bigint = Zeroizing::new(b.0.into_bigint());
        let mut result = [0u64; 4];
        for i in 0..4 {
            result[i] = a_bigint.0[i] ^ (mask & (a_bigint.0[i] ^ b_bigint.0[i]));
        }
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
        match Fr::from_random_bytes(&repr) {
            None => CtOption::new(Self::ZERO, Choice::from(0)),
            Some(k) => CtOption::new(Self(k), Choice::from(1)),
        }
    }

    fn to_repr(&self) -> Self::Repr {
        let mut bytes = Self::Repr::default();
        let mut writer = Cursor::new(&mut bytes[..]);
        self.0.serialize_compressed(&mut writer).expect("Serialization failed");
        bytes
    }

    fn is_odd(&self) -> Choice {
        Choice::from(self.to_repr()[0] & 1)
    }

    const MODULUS: &'static str = MODULUS_STR_FR;
    const NUM_BITS: u32 = 251;
    const CAPACITY: u32 = 250;
    const TWO_INV: Self = Self(INV_2);
    const MULTIPLICATIVE_GENERATOR: Self = Self(Fr::GENERATOR);
    const S: u32 = 4;
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
        bits.copy_from_slice(&SUBORDER_BJJ.to_bytes_le());
        bits.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::{BjjPoint, Scalar};
    use elliptic_curve::Field;
    use group::ff::PrimeField;

    #[test]
    fn serai_group_tests() {
        let mut rng = ark_std::test_rng();
        ff_group_tests::group::test_group::<_, BjjPoint>(&mut rng);
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
}
