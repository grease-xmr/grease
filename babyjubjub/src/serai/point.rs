use crate::{BabyJubJub, ProjectivePoint, Scalar, hash_to_curve, Point};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::RngCore;
use ciphersuite::Ciphersuite;
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

impl From<Point> for BjjPoint {
    fn from(value: Point) -> Self {
        Self(value.into())
    }
}

impl From<BjjPoint> for Point {
    fn from(value: BjjPoint) -> Self {
        value.into()
    }
}

impl ConstantTimeEq for BjjPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
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
            Ok(p) => {
                let p2 = p.into_affine();
                let is_subgroup = p2.is_in_correct_subgroup_assuming_on_curve();
                CtOption::new(BjjPoint(p), Choice::from(is_subgroup as u8))
            }
            Err(_) => CtOption::new(BjjPoint(ProjectivePoint::zero()), Choice::from(0)),
        }
    }

    /// This does not check if the point is on the curve and in the correct subgroup.
    /// Use with caution.
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

pub fn generators() -> [BjjPoint; 2] {
    [BabyJubJub::generator(), {
        let p = hash_to_curve(b"generatorH").expect("hash to curve to to fail here");
        let p: ProjectivePoint = p.into();
        BjjPoint::from(p)
    }]
}

#[cfg(test)]
mod tests {
    use crate::serai::point::generators;
    use ark_ec::CurveGroup;

    #[test]
    fn check_generators() {
        let gens = generators();
        assert_eq!(
            gens[0].0.into_affine().x.to_string(),
            "5299619240641551281634865583518297030282874472190772894086521144482721001553"
        );
        assert_eq!(
            gens[1].0.into_affine().x.to_string(),
            "9841060058308345780925765014991942161616262921351049057566852381813453307315"
        );
    }
}
