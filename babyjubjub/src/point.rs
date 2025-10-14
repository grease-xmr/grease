use crate::{Fq, Fr};
use ark_ec::twisted_edwards::{MontCurveConfig, TECurveConfig};
use ark_ec::{
    models::CurveConfig,
    twisted_edwards::{Affine, Projective},
};
use ark_ff::MontFp;

pub type Point = Affine<BjjConfig>;
pub type ProjectivePoint = Projective<BjjConfig>;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct BjjConfig;

pub use crate::constants::*;

impl CurveConfig for BjjConfig {
    type BaseField = Fq;
    type ScalarField = Fr;
    /// COFACTOR = 8
    const COFACTOR: &'static [u64] = &[8];
    /// COFACTOR_INV (mod r) = 2394026564107420727433200628387514462817212225638746351800188703329891451411
    const COFACTOR_INV: Fr = MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

/// As per https://eips.ethereum.org/EIPS/eip-2494
///
/// The twisted Edwards elliptic curve defined over F_r described by equation
///
/// $ ax^2 + y^2 = 1 + dx^2y^2 $
///
/// with parameters
///
/// a = 168700
/// d = 168696
impl TECurveConfig for BjjConfig {
    const COEFF_A: Self::BaseField = MontFp!("168700");
    const COEFF_D: Self::BaseField = MontFp!("168696");

    const GENERATOR: Point = Point::new_unchecked(B_X_BJJ, B_Y_BJJ);

    type MontCurveConfig = BjjConfig;
}

impl MontCurveConfig for BjjConfig {
    const COEFF_A: Self::BaseField = MontFp!("168698");
    const COEFF_B: Self::BaseField = MontFp!("1");
    type TECurveConfig = BjjConfig;
}

#[cfg(test)]
mod bjj_tests {
    use crate::*;
    use ark_algebra_test_templates::*;
    use ark_ec::twisted_edwards::Affine;
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{Field, MontFp, Zero};
    use ark_serialize::{CanonicalDeserializeWithFlags, CanonicalSerialize, CanonicalSerializeWithFlags, Compress};

    test_group!(te; ProjectivePoint; te);
    test_group!(curve; ProjectivePoint; curve);

    #[test]
    fn addition() {
        let p1 = Affine::<BjjConfig>::new(
            MontFp!("17777552123799933955779906779655732241715742912184938656739573121738514868268"),
            MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475"),
        );
        let p2 = Affine::<BjjConfig>::new(
            MontFp!("16540640123574156134436876038791482806971768689494387082833631921987005038935"),
            MontFp!("20819045374670962167435360035096875258406992893633759881276124905556507972311"),
        );
        let p3 = Affine::<BjjConfig>::new(
            MontFp!("7916061937171219682591368294088513039687205273691143098332585753343424131937"),
            MontFp!("14035240266687799601661095864649209771790948434046947201833777492504781204499"),
        );
        assert_eq!(p1 + p2, p3);
    }

    #[test]
    fn doubling() {
        let p1 = Affine::<BjjConfig>::new(
            MontFp!("17777552123799933955779906779655732241715742912184938656739573121738514868268"),
            MontFp!("2626589144620713026669568689430873010625803728049924121243784502389097019475"),
        );
        let p2 = Affine::<BjjConfig>::new(
            MontFp!("6890855772600357754907169075114257697580319025794532037257385534741338397365"),
            MontFp!("4338620300185947561074059802482547481416142213883829469920100239455078257889"),
        );
        assert_eq!(p1 + p1, p2);
        assert_eq!(p1.mul_bigint(&[2u64]), p2);

        let id = Fq::zero();
        assert_eq!(id + id, id);
    }

    #[test]
    fn base_point() {
        let b = ProjectivePoint::generator();
        let g = Affine::<BjjConfig>::new_unchecked(G_X_BJJ, G_Y_BJJ);
        assert_eq!(g.mul_bigint(&[COFACTOR_BJJ]).into_affine(), b);
    }

    #[test]
    fn base_point_order() {
        let g = ProjectivePoint::generator();
        let inf = g - g;
        assert_eq!(inf, ProjectivePoint::zero());
        assert_eq!(g.mul_bigint(&SUBORDER_BJJ).into_affine(), ProjectivePoint::zero());
    }
}
