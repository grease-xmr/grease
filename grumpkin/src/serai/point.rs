use crate::{Fq, Grumpkin, Point, ProjectivePoint, Scalar, hash_to_curve};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::RngCore;
use ciphersuite::Ciphersuite;
use group::prime::PrimeGroup as SeraiPrimeGroup;
use group::{Group as SeraiGroup, GroupEncoding};
use std::io::Cursor;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct GrumpkinPoint(ProjectivePoint);

impl From<ProjectivePoint> for GrumpkinPoint {
    fn from(value: ProjectivePoint) -> Self {
        Self(value)
    }
}

impl From<Point> for GrumpkinPoint {
    fn from(value: Point) -> Self {
        Self(value.into())
    }
}

impl From<GrumpkinPoint> for Point {
    fn from(value: GrumpkinPoint) -> Self {
        value.0.into_affine()
    }
}

/// Constant-time equality for field elements via BigInt limb comparison.
#[inline]
fn fq_ct_eq(a: &Fq, b: &Fq) -> Choice {
    a.into_bigint().0.ct_eq(&b.into_bigint().0)
}

/// Constant-time selection for field elements.
/// Returns `a` if `choice == 0`, `b` if `choice == 1`.
#[inline]
fn fq_conditional_select(a: &Fq, b: &Fq, choice: Choice) -> Fq {
    let mask = -(choice.unwrap_u8() as i64) as u64;
    let a_limbs = a.into_bigint().0;
    let b_limbs = b.into_bigint().0;
    let result: [u64; 4] = std::array::from_fn(|i| a_limbs[i] ^ (mask & (a_limbs[i] ^ b_limbs[i])));
    Fq::from_bigint(ark_ff::BigInt(result)).unwrap()
}

impl ConditionallySelectable for GrumpkinPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Select each coordinate independently in constant time
        let x = fq_conditional_select(&a.0.x, &b.0.x, choice);
        let y = fq_conditional_select(&a.0.y, &b.0.y, choice);
        let z = fq_conditional_select(&a.0.z, &b.0.z, choice);
        GrumpkinPoint(ProjectivePoint { x, y, z })
    }
}

impl ConstantTimeEq for GrumpkinPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        // For Jacobian coordinates (X, Y, Z), two points P1 and P2 are equal when:
        //   X1 * Z2^2 == X2 * Z1^2  AND  Y1 * Z2^3 == Y2 * Z1^3
        //
        // Special cases:
        // - Both at infinity (Z1 == 0 AND Z2 == 0): equal
        // - Exactly one at infinity: not equal
        // - Neither at infinity: compare cross-multiplied coordinates

        let z1_is_zero = fq_ct_eq(&self.0.z, &Fq::ZERO);
        let z2_is_zero = fq_ct_eq(&other.0.z, &Fq::ZERO);

        // Compute cross-multiplied coordinates
        let z1z1 = self.0.z.square();
        let z2z2 = other.0.z.square();

        // X1 * Z2^2 vs X2 * Z1^2
        let lhs_x = self.0.x * z2z2;
        let rhs_x = other.0.x * z1z1;
        let x_eq = fq_ct_eq(&lhs_x, &rhs_x);

        // Y1 * Z2^3 vs Y2 * Z1^3
        let lhs_y = self.0.y * (z2z2 * other.0.z);
        let rhs_y = other.0.y * (z1z1 * self.0.z);
        let y_eq = fq_ct_eq(&lhs_y, &rhs_y);

        // Both at infinity => equal
        let both_infinity = z1_is_zero & z2_is_zero;

        // Neither at infinity and coordinates match => equal
        let neither_infinity = !z1_is_zero & !z2_is_zero;
        let coords_match = x_eq & y_eq;

        both_infinity | (neither_infinity & coords_match)
    }
}

impl SeraiPrimeGroup for GrumpkinPoint {}

impl SeraiGroup for GrumpkinPoint {
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

impl GroupEncoding for GrumpkinPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        let reader = Cursor::new(bytes);
        match ProjectivePoint::deserialize_compressed(reader) {
            Ok(p) => {
                // Grumpkin has cofactor 1, so all points on the curve are in the correct subgroup
                CtOption::new(GrumpkinPoint(p), Choice::from(1))
            }
            Err(_) => CtOption::new(GrumpkinPoint(ProjectivePoint::zero()), Choice::from(0)),
        }
    }

    /// This does not check if the point is on the curve.
    /// Use with caution.
    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        let reader = Cursor::new(bytes);
        match ProjectivePoint::deserialize_compressed_unchecked(reader) {
            Ok(p) => CtOption::new(GrumpkinPoint(p), Choice::from(1)),
            Err(_) => CtOption::new(GrumpkinPoint(ProjectivePoint::zero()), Choice::from(0)),
        }
    }

    fn to_bytes(&self) -> Self::Repr {
        let mut bytes = [0u8; 32];
        let mut writer = Cursor::new(&mut bytes[..]);
        self.0.serialize_compressed(&mut writer).expect("Serialization failed");
        bytes
    }
}

impl Sum for GrumpkinPoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let sum = iter.fold(ProjectivePoint::zero(), |acc, x| acc + x.0);
        GrumpkinPoint(sum)
    }
}

impl<'a> Sum<&'a GrumpkinPoint> for GrumpkinPoint {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        let sum = iter.fold(ProjectivePoint::zero(), |acc, x| acc + x.0);
        GrumpkinPoint(sum)
    }
}

impl Neg for GrumpkinPoint {
    type Output = Self;

    fn neg(self) -> Self::Output {
        GrumpkinPoint(-self.0)
    }
}

impl Add<Self> for GrumpkinPoint {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        GrumpkinPoint(self.0 + rhs.0)
    }
}

impl Sub<Self> for GrumpkinPoint {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        GrumpkinPoint(self.0 - rhs.0)
    }
}

impl AddAssign<Self> for GrumpkinPoint {
    fn add_assign(&mut self, rhs: Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl SubAssign<Self> for GrumpkinPoint {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl Add<&Self> for GrumpkinPoint {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        GrumpkinPoint(self.0 + rhs.0)
    }
}

impl Sub<&Self> for GrumpkinPoint {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        GrumpkinPoint(self.0 - rhs.0)
    }
}

impl AddAssign<&Self> for GrumpkinPoint {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = self.0 + rhs.0;
    }
}

impl SubAssign<&Self> for GrumpkinPoint {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = self.0 - rhs.0;
    }
}

impl Mul<Scalar> for GrumpkinPoint {
    type Output = Self;

    fn mul(self, rhs: Scalar) -> Self::Output {
        GrumpkinPoint(self.0.mul(rhs.0))
    }
}

impl Mul<&Scalar> for GrumpkinPoint {
    type Output = Self;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        GrumpkinPoint(self.0.mul(&rhs.0))
    }
}

impl MulAssign<Scalar> for GrumpkinPoint {
    fn mul_assign(&mut self, rhs: Scalar) {
        self.0.mul_assign(rhs.0);
    }
}

impl MulAssign<&Scalar> for GrumpkinPoint {
    fn mul_assign(&mut self, rhs: &Scalar) {
        self.0.mul_assign(&rhs.0);
    }
}

/// Returns the two generators [G, H] for Grumpkin.
/// G is the standard generator, H is derived via hash-to-curve.
pub fn generators() -> [GrumpkinPoint; 2] {
    [Grumpkin::generator(), {
        let p = hash_to_curve(b"generatorH").expect("hash to curve not to fail here");
        let p: ProjectivePoint = p.into();
        GrumpkinPoint::from(p)
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::MontFp;
    use ark_grumpkin::Fq;
    use group::GroupEncoding;

    #[test]
    fn check_generators() {
        let [g, h] = generators();
        let g = g.0.into_affine();
        let h = h.0.into_affine();

        // G is the standard Grumpkin generator: (1, sqrt(-16))
        assert_eq!(
            g.x,
            MontFp!("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            g.y,
            MontFp!("0x0000000000000002cf135e7506a45d632d270d45f1181294833fc48d823f272c")
        );

        // H is derived from hash_to_curve(b"generatorH")
        assert_eq!(
            h.x,
            MontFp!("0x10863a55e0a22bf92ed78688905fa12a12d0028e224456ad72a5bf2fb564288a")
        );
        assert_eq!(
            h.y,
            MontFp!("0x16a647f6f409cbd85a95b85d986cc95486248ce34b3a6ba0b8cc9656b0fd7ef6")
        );
    }

    #[test]
    fn point_encoding_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let p = GrumpkinPoint::random(&mut rng);
            let bytes = p.to_bytes();
            let p2 = GrumpkinPoint::from_bytes(&bytes).unwrap();
            assert_eq!(p, p2);
        }
    }

    #[test]
    fn identity_encoding() {
        let id = GrumpkinPoint::identity();
        let bytes = id.to_bytes();
        let id2 = GrumpkinPoint::from_bytes(&bytes).unwrap();
        assert_eq!(id, id2);
    }

    // Test vectors from https://github.com/lurk-lab/solidity-verifier/blob/main/test/grumpkin-curves-tests.t.sol

    /// Helper to create a GrumpkinPoint from x,y field element strings
    fn point_from_xy(x: Fq, y: Fq) -> GrumpkinPoint {
        let affine = Point::new(x, y);
        assert!(affine.is_on_curve(), "Test vector point not on curve");
        GrumpkinPoint::from(affine)
    }

    #[test]
    fn test_vector_point_addition() {
        // Test vector 1 from solidity-verifier
        let a = point_from_xy(
            MontFp!("0x1cccccb80012e70dd67726216a7d958066d2df2ab126eab550c9e57cc02eaf88"),
            MontFp!("0x0a5809d7d9f66ae7e22107f71bbe8f6f1d980eb0254903eeb17e46255a5758bb"),
        );
        let b = point_from_xy(
            MontFp!("0x0eb7400597f60115135a47416a82e673ada930a84d61fdcff6238b7432f5cc4a"),
            MontFp!("0x1b6b2a54c04eb0830097f90e5792465b5c131599e1cd9646539ef175d9eac362"),
        );
        let expected = point_from_xy(
            MontFp!("0x20f8a568a0f88b810c1e188bed483c59d3bc9580961189610a3417c1d059988d"),
            MontFp!("0x129ddaf2d82686acfaf2027286ff4863518f2f287cfd260764b3882db95c5aae"),
        );

        let result = a + b;
        assert_eq!(result, expected, "Point addition test vector 1 failed");
    }

    #[test]
    fn test_vector_identity_addition() {
        // Adding identity to identity should yield identity
        let id = GrumpkinPoint::identity();
        let result = id + id;
        assert_eq!(result, id, "Identity + Identity should be Identity");

        // Adding identity to a point should yield the same point
        let p = point_from_xy(
            MontFp!("0x1cccccb80012e70dd67726216a7d958066d2df2ab126eab550c9e57cc02eaf88"),
            MontFp!("0x0a5809d7d9f66ae7e22107f71bbe8f6f1d980eb0254903eeb17e46255a5758bb"),
        );
        assert_eq!(p + id, p, "P + Identity should be P");
        assert_eq!(id + p, p, "Identity + P should be P");
    }

    #[test]
    fn test_vector_scalar_multiplication() {
        use ark_ff::MontFp as MontFpFr;

        // Test vector from solidity-verifier
        let scalar = Scalar(MontFpFr!("0x29bd9a803cd11224817183fc6bceb32d59926fd9aa37d3cfb1c7845cbf7fae0d"));
        let point = point_from_xy(
            MontFp!("0x0a457db8ec3235bd290311c7aa8356a7cbb24771a3ed0ccfb5d276953bef3aca"),
            MontFp!("0x0d7a2a8c2a155df8c022c1f953e622e81e792d3bcf68e1d5d26eb13064a31b22"),
        );
        let expected = point_from_xy(
            MontFp!("0x23a8467859c9d32cf98c6ca74480024400f95c161808ad6477a993137612e0ad"),
            MontFp!("0x1ff011d011d6988453b220017339c1bfe7906f266d8becdce5c733993bf17772"),
        );

        let result = point * scalar;
        assert_eq!(result, expected, "Scalar multiplication test vector failed");
    }

    #[test]
    fn test_vector_point_negation() {
        // Negating a point should flip the y-coordinate
        let p = point_from_xy(
            MontFp!("0x0eb7400597f60115135a47416a82e673ada930a84d61fdcff6238b7432f5cc4a"),
            MontFp!("0x1b6b2a54c04eb0830097f90e5792465b5c131599e1cd9646539ef175d9eac362"),
        );
        let neg_p = -p;

        // P + (-P) should equal identity
        let sum = p + neg_p;
        assert!(bool::from(sum.is_identity()), "P + (-P) should be identity");

        // Negating twice should return original point
        let neg_neg_p = -neg_p;
        assert_eq!(neg_neg_p, p, "Double negation should return original point");
    }

    #[test]
    fn test_vector_point_doubling() {
        // Test that P + P equals 2*P
        let p = point_from_xy(
            MontFp!("0x1cccccb80012e70dd67726216a7d958066d2df2ab126eab550c9e57cc02eaf88"),
            MontFp!("0x0a5809d7d9f66ae7e22107f71bbe8f6f1d980eb0254903eeb17e46255a5758bb"),
        );

        let doubled_via_add = p + p;
        let doubled_via_method = p.double();
        let doubled_via_scalar = p * Scalar::from(2u64);

        assert_eq!(doubled_via_add, doubled_via_method, "P + P should equal double(P)");
        assert_eq!(doubled_via_add, doubled_via_scalar, "P + P should equal 2*P");
    }

    #[test]
    fn test_vector_scalar_mul_identity() {
        let p = point_from_xy(
            MontFp!("0x0a457db8ec3235bd290311c7aa8356a7cbb24771a3ed0ccfb5d276953bef3aca"),
            MontFp!("0x0d7a2a8c2a155df8c022c1f953e622e81e792d3bcf68e1d5d26eb13064a31b22"),
        );

        // Multiplying by 0 should give identity
        let zero_result = p * Scalar::from(0u64);
        assert!(bool::from(zero_result.is_identity()), "P * 0 should be identity");

        // Multiplying by 1 should give the same point
        let one_result = p * Scalar::from(1u64);
        assert_eq!(one_result, p, "P * 1 should be P");
    }

    #[test]
    fn test_point_subtraction() {
        let a = point_from_xy(
            MontFp!("0x1cccccb80012e70dd67726216a7d958066d2df2ab126eab550c9e57cc02eaf88"),
            MontFp!("0x0a5809d7d9f66ae7e22107f71bbe8f6f1d980eb0254903eeb17e46255a5758bb"),
        );
        let b = point_from_xy(
            MontFp!("0x0eb7400597f60115135a47416a82e673ada930a84d61fdcff6238b7432f5cc4a"),
            MontFp!("0x1b6b2a54c04eb0830097f90e5792465b5c131599e1cd9646539ef175d9eac362"),
        );

        // (A + B) - B should equal A
        let sum = a + b;
        let diff = sum - b;
        assert_eq!(diff, a, "(A + B) - B should equal A");

        // A - A should be identity
        let self_sub = a - a;
        assert!(bool::from(self_sub.is_identity()), "A - A should be identity");
    }

    // ==================== From/Into conversion tests ====================

    #[test]
    fn from_projective_point() {
        let proj = ProjectivePoint::generator();
        let grump: GrumpkinPoint = proj.into();
        assert_eq!(grump, GrumpkinPoint::generator());
    }

    #[test]
    fn from_affine_point() {
        let affine = Point::generator();
        let grump: GrumpkinPoint = affine.into();
        assert_eq!(grump, GrumpkinPoint::generator());
    }

    #[test]
    fn into_affine_point() {
        let grump = GrumpkinPoint::generator();
        let affine: Point = grump.into();
        assert_eq!(affine, Point::generator());
    }

    #[test]
    fn conversion_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let p = GrumpkinPoint::random(&mut rng);
            let affine: Point = p.into();
            let back: GrumpkinPoint = affine.into();
            assert_eq!(p, back);
        }
    }

    // ==================== ConstantTimeEq tests ====================

    #[test]
    fn constant_time_eq() {
        let g = GrumpkinPoint::generator();
        let g2 = GrumpkinPoint::generator();
        let id = GrumpkinPoint::identity();

        assert!(bool::from(g.ct_eq(&g2)));
        assert!(!bool::from(g.ct_eq(&id)));
        assert!(bool::from(id.ct_eq(&GrumpkinPoint::identity())));
    }

    #[test]
    fn constant_time_eq_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let p = GrumpkinPoint::random(&mut rng);
            let p2 = p;
            assert!(bool::from(p.ct_eq(&p2)));

            let q = GrumpkinPoint::random(&mut rng);
            // Random points are almost certainly different
            if p != q {
                assert!(!bool::from(p.ct_eq(&q)));
            }
        }
    }

    // ==================== ConditionallySelectable tests ====================

    #[test]
    fn conditional_select() {
        let g = GrumpkinPoint::generator();
        let id = GrumpkinPoint::identity();

        // choice = 0 selects first argument
        let sel_g = GrumpkinPoint::conditional_select(&g, &id, Choice::from(0));
        assert_eq!(sel_g, g);

        // choice = 1 selects second argument
        let sel_id = GrumpkinPoint::conditional_select(&g, &id, Choice::from(1));
        assert_eq!(sel_id, id);
    }

    #[test]
    fn conditional_select_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let a = GrumpkinPoint::random(&mut rng);
            let b = GrumpkinPoint::random(&mut rng);

            let sel_a = GrumpkinPoint::conditional_select(&a, &b, Choice::from(0));
            let sel_b = GrumpkinPoint::conditional_select(&a, &b, Choice::from(1));

            assert_eq!(sel_a, a);
            assert_eq!(sel_b, b);
        }
    }

    #[test]
    fn conditional_select_identity() {
        let id = GrumpkinPoint::identity();
        let g = GrumpkinPoint::generator();

        // Selecting between identity and non-identity
        let sel0 = GrumpkinPoint::conditional_select(&id, &g, Choice::from(0));
        let sel1 = GrumpkinPoint::conditional_select(&id, &g, Choice::from(1));

        assert!(bool::from(sel0.is_identity()));
        assert!(!bool::from(sel1.is_identity()));
        assert_eq!(sel1, g);
    }

    // ==================== Group trait tests ====================

    #[test]
    fn group_identity() {
        let id = GrumpkinPoint::identity();
        assert!(bool::from(id.is_identity()));
        assert!(!bool::from(GrumpkinPoint::generator().is_identity()));
    }

    #[test]
    fn group_generator() {
        let g = GrumpkinPoint::generator();
        let g_affine: Point = g.into();
        assert!(g_affine.is_on_curve());
        assert!(!bool::from(g.is_identity()));
    }

    #[test]
    fn group_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let p = GrumpkinPoint::random(&mut rng);
            let affine: Point = p.into();
            assert!(affine.is_on_curve());
        }
    }

    #[test]
    fn group_double() {
        let g = GrumpkinPoint::generator();
        let doubled = g.double();
        assert_eq!(doubled, g + g);
        assert_eq!(GrumpkinPoint::identity().double(), GrumpkinPoint::identity());
    }

    #[test]
    fn repeated_addition_equals_scalar_mul() {
        let mut rng = ark_std::test_rng();

        // Test with generator
        let g = GrumpkinPoint::generator();
        for k in 0u64..=17 {
            let mut sum = GrumpkinPoint::identity();
            for _ in 0..k {
                sum = sum + g;
            }
            let scalar_mul = g * Scalar::from(k);
            assert_eq!(sum, scalar_mul, "Repeated addition failed for k={k}");
        }

        // Test with random points
        for _ in 0..10 {
            let p = GrumpkinPoint::random(&mut rng);
            for k in 0u64..=17 {
                let mut sum = GrumpkinPoint::identity();
                for _ in 0..k {
                    sum = sum + p;
                }
                let scalar_mul = p * Scalar::from(k);
                assert_eq!(sum, scalar_mul, "Repeated addition failed for random point, k={k}");
            }
        }
    }

    // ==================== GroupEncoding tests ====================

    #[test]
    fn from_bytes_invalid() {
        // Random garbage should fail (0xFF... is >= field modulus)
        let garbage: [u8; 32] = [0xFF; 32];
        let result = GrumpkinPoint::from_bytes(&garbage);
        assert!(bool::from(result.is_none()));

        // All zeros is not a valid point on Grumpkin (x=0 gives y^2 = -17, which has no sqrt)
        let zeros = [0u8; 32];
        let result = GrumpkinPoint::from_bytes(&zeros);
        assert!(bool::from(result.is_none()));

        // Test that identity point roundtrips correctly
        let id = GrumpkinPoint::identity();
        let id_bytes = id.to_bytes();
        let id2 = GrumpkinPoint::from_bytes(&id_bytes).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn from_bytes_unchecked_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let p = GrumpkinPoint::random(&mut rng);
            let bytes = p.to_bytes();
            // from_bytes_unchecked should work for valid encodings
            let p2 = GrumpkinPoint::from_bytes_unchecked(&bytes).unwrap();
            assert_eq!(p, p2);
        }
    }

    // ==================== Arithmetic operator tests ====================

    #[test]
    fn add_ref_variants() {
        let a = GrumpkinPoint::generator();
        let b = GrumpkinPoint::generator().double();

        // Add owned
        let sum1 = a + b;
        // Add reference
        let sum2 = a + &b;

        assert_eq!(sum1, sum2);
    }

    #[test]
    fn sub_ref_variants() {
        let a = GrumpkinPoint::generator().double();
        let b = GrumpkinPoint::generator();

        // Sub owned
        let diff1 = a - b;
        // Sub reference
        let diff2 = a - &b;

        assert_eq!(diff1, diff2);
        assert_eq!(diff1, GrumpkinPoint::generator());
    }

    #[test]
    fn add_assign_variants() {
        let mut a = GrumpkinPoint::generator();
        let b = GrumpkinPoint::generator();

        a += b;
        assert_eq!(a, GrumpkinPoint::generator().double());

        a += &b;
        assert_eq!(a, GrumpkinPoint::generator().double() + GrumpkinPoint::generator());
    }

    #[test]
    fn sub_assign_variants() {
        let mut a = GrumpkinPoint::generator().double();
        let b = GrumpkinPoint::generator();

        a -= b;
        assert_eq!(a, GrumpkinPoint::generator());

        a -= &b;
        assert!(bool::from(a.is_identity()));
    }

    #[test]
    fn mul_ref_variants() {
        let p = GrumpkinPoint::generator();
        let s = Scalar::from(5u64);

        // Mul owned
        let prod1 = p * s;
        // Mul reference
        let prod2 = p * &s;

        assert_eq!(prod1, prod2);
    }

    #[test]
    fn mul_assign_variants() {
        let mut p = GrumpkinPoint::generator();
        let s = Scalar::from(2u64);

        p *= s;
        assert_eq!(p, GrumpkinPoint::generator().double());

        p *= &s;
        assert_eq!(p, GrumpkinPoint::generator().double().double());
    }

    // ==================== Sum tests ====================

    #[test]
    fn sum_owned() {
        let g = GrumpkinPoint::generator();
        let points = vec![g, g, g];
        let sum: GrumpkinPoint = points.into_iter().sum();
        assert_eq!(sum, g * Scalar::from(3u64));

        // Empty sum should be identity
        let empty: Vec<GrumpkinPoint> = vec![];
        let empty_sum: GrumpkinPoint = empty.into_iter().sum();
        assert!(bool::from(empty_sum.is_identity()));
    }

    #[test]
    fn sum_refs() {
        let g = GrumpkinPoint::generator();
        let points = vec![g, g, g, g];
        let sum: GrumpkinPoint = points.iter().sum();
        assert_eq!(sum, g * Scalar::from(4u64));
    }

    // ==================== Zeroize test ====================

    #[test]
    fn zeroize() {
        use zeroize::Zeroize;

        let mut p = GrumpkinPoint::generator();
        p.zeroize();
        // After zeroize, the point should be the identity (all zeros)
        assert!(bool::from(p.is_identity()));
    }

    // ==================== Multi-scalar multiplication test vectors ====================
    // Test vectors from https://github.com/lurk-lab/solidity-verifier/blob/main/test/multiscalar-mul-tests.t.sol

    #[test]
    fn test_vector_msm_8_points() {
        use ark_ff::MontFp as MontFpFr;

        // 8 base points from testGrumpkin3Serial
        let bases = [
            point_from_xy(
                MontFp!("0x15afa1c1de43e186ee615ee76389d1ca9de572d426869ab062a03f1ba65808a2"),
                MontFp!("0x28d6d43cb5ba89778111ceaa56cb8bf2c34a5fb6013988513d5798a60846d423"),
            ),
            point_from_xy(
                MontFp!("0x132126b357d7299c5c18e04cbe13c4206b763dbc56a8d19900270cd0c59f3981"),
                MontFp!("0x169077205c0ed8e9f2738a9f04d064e17c457a531a93e9ec5131e35d587cd381"),
            ),
            point_from_xy(
                MontFp!("0x20c9d6e3d55f0142ce09b6d1cd8b86c8eaecf8f204bce4c9b88a75c720e34b74"),
                MontFp!("0x227f66a87a7649e8a76a2314e14c0c44877e1eca54015d5ecd8b1da08ccbb779"),
            ),
            point_from_xy(
                MontFp!("0x1300fe5112d72be0b65d1d365f294a136df15671e4f56e2fbf65be2ffec64e4f"),
                MontFp!("0x0c93e3b91eeead0adf19f228e2a361b3b6055d1b89e699196c6a5550be5824b9"),
            ),
            point_from_xy(
                MontFp!("0x00561f915062be50a6f0b4966c812394f6209e305eaba304eb0442bd8658db3f"),
                MontFp!("0x101fd2e6e6f14f80c5d5b851f75f377aa4a9fa70feee973acab6c085ba390b31"),
            ),
            point_from_xy(
                MontFp!("0x2c6ac455956eeab7124f2b7468d14731b082a76b33b30bfa5cd4286652646cc7"),
                MontFp!("0x0c9f73a8296c89a7e4a85cc17920b2988a5f1fabb0738dfc2399b4c0bd5823f9"),
            ),
            point_from_xy(
                MontFp!("0x295a7a5268032eeabea8d38dbf482721c2d2eb96e9bc113225e6cc97bf931d1b"),
                MontFp!("0x18eceee12552137b0d09e35056e944a618f8103cb408191edd8c5e9f92bae99c"),
            ),
            point_from_xy(
                MontFp!("0x1fb6c4c5970ecb51f1970e9b2a214ea88079d598df36d784140b7b81463eb90b"),
                MontFp!("0x07bb64def7fed9c68d8542e22afad6995481615e7a7185cd695105b482d05180"),
            ),
        ];

        // 8 scalars
        let scalars = [
            Scalar(MontFpFr!("0x1a8e54bfe01d0d0cb3f43427a4e4d17b5433c0da1fe2afdde034c1c1930f7f7d")),
            Scalar(MontFpFr!("0x0a3ba18282db74f05d05e71329fa6c7a31b5b5ab5a1dc3ebace94d3863e48983")),
            Scalar(MontFpFr!("0x073fe7f0c2a1b32d93f3cc1041c9fdb09e5f94be09e6a17b28ab1e3954e5a567")),
            Scalar(MontFpFr!("0x1ed4bae9714e4e28fc63fdcc1b54b1f4ac8ec079aca2cca4b92b7e45d63b1395")),
            Scalar(MontFpFr!("0x1cb0ba55ddf67148f5fa7a8ef3f9c8cafdfe56bea23b1d5a6253e0857e56ad82")),
            Scalar(MontFpFr!("0x440d065f48ded1fe82dfffa571aa3875c0496b9821e0bff98c9a24e69065488a")),
            Scalar(MontFpFr!("0x1b32544e236d677739086e7725aa4ae01f1a664092225af076a4fb72f1002e75")),
            Scalar(MontFpFr!("0x5325e7f1c0e1bf320bc2649d3b5764d8795abcf137d8325b3fbf3198774085e1")),
        ];

        // Expected result: sum(scalar_i * base_i)
        let expected = point_from_xy(
            MontFp!("0x14df709e5f2820818a45604d280f1a21088aeee4b37cbc7ba41a7fe9b2005c41"),
            MontFp!("0x1780bfb139af4e3905ab498d514d1cbbab9e0bc2839fdfdf18464ff857cb6b4c"),
        );

        // Compute MSM: sum(scalar_i * base_i)
        let result: GrumpkinPoint = bases.iter().zip(scalars.iter()).map(|(base, scalar)| *base * *scalar).sum();

        assert_eq!(result, expected, "MSM with 8 points failed");
    }

    #[test]
    fn test_vector_individual_scalar_muls() {
        use ark_ff::MontFp as MontFpFr;

        // Test individual scalar multiplications from the MSM test vectors
        // This verifies each scalar * point computation independently

        // Point 0 * Scalar 0
        let p0 = point_from_xy(
            MontFp!("0x15afa1c1de43e186ee615ee76389d1ca9de572d426869ab062a03f1ba65808a2"),
            MontFp!("0x28d6d43cb5ba89778111ceaa56cb8bf2c34a5fb6013988513d5798a60846d423"),
        );
        let s0 = Scalar(MontFpFr!("0x1a8e54bfe01d0d0cb3f43427a4e4d17b5433c0da1fe2afdde034c1c1930f7f7d"));
        let result0 = p0 * s0;

        // Verify result is on curve
        let affine0: Point = result0.into();
        assert!(affine0.is_on_curve(), "Scalar mul result not on curve");

        // Point 1 * Scalar 1
        let p1 = point_from_xy(
            MontFp!("0x132126b357d7299c5c18e04cbe13c4206b763dbc56a8d19900270cd0c59f3981"),
            MontFp!("0x169077205c0ed8e9f2738a9f04d064e17c457a531a93e9ec5131e35d587cd381"),
        );
        let s1 = Scalar(MontFpFr!("0x0a3ba18282db74f05d05e71329fa6c7a31b5b5ab5a1dc3ebace94d3863e48983"));
        let result1 = p1 * s1;

        let affine1: Point = result1.into();
        assert!(affine1.is_on_curve(), "Scalar mul result not on curve");

        // Verify commutativity-like property: (a+b)*P = a*P + b*P
        let a = Scalar(MontFpFr!("0x1a8e54bfe01d0d0cb3f43427a4e4d17b5433c0da1fe2afdde034c1c1930f7f7d"));
        let b = Scalar(MontFpFr!("0x0a3ba18282db74f05d05e71329fa6c7a31b5b5ab5a1dc3ebace94d3863e48983"));
        let p = point_from_xy(
            MontFp!("0x20c9d6e3d55f0142ce09b6d1cd8b86c8eaecf8f204bce4c9b88a75c720e34b74"),
            MontFp!("0x227f66a87a7649e8a76a2314e14c0c44877e1eca54015d5ecd8b1da08ccbb779"),
        );

        let lhs = p * (a + b);
        let rhs = (p * a) + (p * b);
        assert_eq!(lhs, rhs, "Distributive property failed: (a+b)*P != a*P + b*P");
    }

    #[test]
    fn test_vector_msm_associativity() {
        use ark_ff::MontFp as MontFpFr;

        // Verify associativity: sum in different orders should give same result
        let bases = [
            point_from_xy(
                MontFp!("0x15afa1c1de43e186ee615ee76389d1ca9de572d426869ab062a03f1ba65808a2"),
                MontFp!("0x28d6d43cb5ba89778111ceaa56cb8bf2c34a5fb6013988513d5798a60846d423"),
            ),
            point_from_xy(
                MontFp!("0x132126b357d7299c5c18e04cbe13c4206b763dbc56a8d19900270cd0c59f3981"),
                MontFp!("0x169077205c0ed8e9f2738a9f04d064e17c457a531a93e9ec5131e35d587cd381"),
            ),
            point_from_xy(
                MontFp!("0x20c9d6e3d55f0142ce09b6d1cd8b86c8eaecf8f204bce4c9b88a75c720e34b74"),
                MontFp!("0x227f66a87a7649e8a76a2314e14c0c44877e1eca54015d5ecd8b1da08ccbb779"),
            ),
            point_from_xy(
                MontFp!("0x1300fe5112d72be0b65d1d365f294a136df15671e4f56e2fbf65be2ffec64e4f"),
                MontFp!("0x0c93e3b91eeead0adf19f228e2a361b3b6055d1b89e699196c6a5550be5824b9"),
            ),
        ];

        let scalars = [
            Scalar(MontFpFr!("0x1a8e54bfe01d0d0cb3f43427a4e4d17b5433c0da1fe2afdde034c1c1930f7f7d")),
            Scalar(MontFpFr!("0x0a3ba18282db74f05d05e71329fa6c7a31b5b5ab5a1dc3ebace94d3863e48983")),
            Scalar(MontFpFr!("0x073fe7f0c2a1b32d93f3cc1041c9fdb09e5f94be09e6a17b28ab1e3954e5a567")),
            Scalar(MontFpFr!("0x1ed4bae9714e4e28fc63fdcc1b54b1f4ac8ec079aca2cca4b92b7e45d63b1395")),
        ];

        // Forward sum
        let forward: GrumpkinPoint = bases.iter().zip(scalars.iter()).map(|(b, s)| *b * *s).sum();

        // Reverse sum
        let reverse: GrumpkinPoint = bases.iter().zip(scalars.iter()).rev().map(|(b, s)| *b * *s).sum();

        // Pairwise sum: (s0*P0 + s1*P1) + (s2*P2 + s3*P3)
        let pair1 = (bases[0] * scalars[0]) + (bases[1] * scalars[1]);
        let pair2 = (bases[2] * scalars[2]) + (bases[3] * scalars[3]);
        let pairwise = pair1 + pair2;

        assert_eq!(forward, reverse, "MSM sum order should not matter");
        assert_eq!(forward, pairwise, "MSM associativity failed");
    }
}
