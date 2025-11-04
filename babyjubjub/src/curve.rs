use crate::fields::FqHasher;
use crate::{BjjConfig, Fq, Point, ProjectivePoint};
use ark_ec::hashing::curve_maps::elligator2::{Elligator2Config, Elligator2Map};
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::{HashToCurve, HashToCurveError};
use ark_ff::MontFp;

impl Elligator2Config for BjjConfig {
    /// Calculated using [the recommended algorithm](https://www.rfc-editor.org/rfc/rfc9380.html#elligator-z-code)
    const Z: Fq = MontFp!("5");
    const ONE_OVER_COEFF_B_SQUARE: Fq = MontFp!("1");
    const COEFF_A_OVER_COEFF_B: Fq = MontFp!("168698");
}

pub type ToBjjCurveHasher = MapToCurveBasedHasher<ProjectivePoint, FqHasher, Elligator2Map<BjjConfig>>;

const HASH_TO_CURVE_DOMAIN: &[u8] = b"BabyJubJub_XMD:Blake2b-512_ELL2_RO";
pub fn hash_to_curve(msg: &[u8]) -> Result<Point, HashToCurveError> {
    let hasher = ToBjjCurveHasher::new(HASH_TO_CURVE_DOMAIN)?;
    hasher.hash(msg)
}

#[cfg(test)]
mod tests {
    use crate::{BjjConfig, hash_to_curve};
    use ark_ec::hashing::curve_maps::elligator2::Elligator2Config;
    use ark_ec::twisted_edwards::MontCurveConfig;
    use ark_ff::Field;

    #[test]
    #[expect(non_snake_case)]
    fn check_parameters() {
        let A = <BjjConfig as MontCurveConfig>::COEFF_A;
        let B = <BjjConfig as MontCurveConfig>::COEFF_B;
        assert_eq!(A / B, BjjConfig::COEFF_A_OVER_COEFF_B);
        assert_eq!(B.square().inverse().unwrap(), BjjConfig::ONE_OVER_COEFF_B_SQUARE);
        assert!(<BjjConfig as Elligator2Config>::Z.sqrt().is_none());
    }

    #[test]
    fn message_to_curve() {
        let msg = b"Hello, world!";
        let p = hash_to_curve(msg).unwrap();
        assert!(p.is_on_curve());
        assert_eq!(
            p.x.to_string(),
            "13006301608839310497391545708168326660349991855066312545305121243630835537998"
        );
        assert_eq!(
            p.y.to_string(),
            "19431021847877467251427999331976814757933307956599515132869127447508428432163"
        );
    }
}
