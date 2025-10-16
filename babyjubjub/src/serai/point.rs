use crate::{Fq, ProjectivePoint, Scalar};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::RngCore;
use group::{Group as SeraiGroup, GroupEncoding, prime::PrimeGroup as SeraiPrimeGroup};
use std::io::Cursor;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct BjjPoint(ProjectivePoint);

impl From<ProjectivePoint> for BjjPoint {
    fn from(value: ProjectivePoint) -> Self {
        Self(value)
    }
}

impl ConstantTimeEq for BjjPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        #[inline]
        fn cmp_ct(a: &Fq, b: &Fq) -> Choice {
            let a = a.into_bigint();
            let b = b.into_bigint();
            a.0.ct_eq(&b.0)
        }
        let r = self.0.into_affine();
        let s = other.0.into_affine();
        cmp_ct(&r.x, &s.x) & cmp_ct(&r.y, &s.y)
    }
}

impl SeraiPrimeGroup for BjjPoint {}

impl SeraiGroup for BjjPoint {
    type Scalar = Scalar;

    fn random(mut rng: impl RngCore) -> Self {
        ProjectivePoint::rand(&mut rng).into()
    }

    fn identity() -> Self {
        ProjectivePoint::ZERO.into()
    }

    fn generator() -> Self {
        ProjectivePoint::generator().into()
    }

    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::identity())
    }

    fn double(&self) -> Self {
        self.0.double().into()
    }
}

impl GroupEncoding for BjjPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let reader = Cursor::new(bytes);
        match ProjectivePoint::deserialize_compressed(reader) {
            Ok(p) => CtOption::new(BjjPoint(p), Choice::from(1)),
            Err(_) => CtOption::new(BjjPoint(ProjectivePoint::zero()), Choice::from(0)),
        }
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let reader = Cursor::new(bytes);
        match ProjectivePoint::deserialize_compressed_unchecked(reader) {
            Ok(p) => CtOption::new(BjjPoint(p), Choice::from(1)),
            Err(_) => CtOption::new(BjjPoint(ProjectivePoint::zero()), Choice::from(0)),
        }
    }

    fn to_bytes(&self) -> Self::Repr {
        let mut bytes = [0u8; 32];
        let mut writer = Cursor::new(&mut bytes[..]);
        self.0.serialize_compressed(&mut writer).expect("Serialization failed");
        bytes
    }
}

impl Sum for BjjPoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.fold(ProjectivePoint::zero(), |acc, x| acc + x.0);
        BjjPoint(sum)
    }
}

impl<'a> Sum<&'a BjjPoint> for BjjPoint {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let sum = iter.fold(ProjectivePoint::zero(), |acc, x| acc + x.0);
        BjjPoint(sum)
    }
}

impl Neg for BjjPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        BjjPoint(-self.0)
    }
}

impl Add<Self> for BjjPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        BjjPoint(self.0 + rhs.0)
    }
}

impl Sub<Self> for BjjPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        BjjPoint(self.0 - rhs.0)
    }
}

impl AddAssign<Self> for BjjPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl SubAssign<Self> for BjjPoint {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl Add<&Self> for BjjPoint {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        BjjPoint(self.0 + rhs.0)
    }
}

impl Sub<&Self> for BjjPoint {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        BjjPoint(self.0 - rhs.0)
    }
}

impl AddAssign<&Self> for BjjPoint {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl SubAssign<&Self> for BjjPoint {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl Mul<Scalar> for BjjPoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        BjjPoint(self.0.mul(rhs.0))
    }
}

impl Mul<&Scalar> for BjjPoint {
    type Output = Self;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        BjjPoint(self.0.mul(&rhs.0))
    }
}

impl MulAssign<Scalar> for BjjPoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        self.0.mul_assign(rhs.0);
    }
}

impl MulAssign<&Scalar> for BjjPoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0.mul_assign(&rhs.0);
    }
}
