use crate::{BjjPoint, Scalar, hash_to_fr};
use blake2::Blake2b512;
use ciphersuite::Ciphersuite;
use group::Group;
use modular_frost::curve::Curve as FrostCurve;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct BabyJubJub;

impl Ciphersuite for BabyJubJub {
    type F = Scalar;
    type G = BjjPoint;
    type H = Blake2b512;

    const ID: &'static [u8] = b"BJJ-255-Blake2b-v1";

    fn generator() -> Self::G {
        BjjPoint::generator()
    }

    #[allow(non_snake_case)]
    fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
        // hash_to_curve already uses proper DST, but we will mix in the dst here as well
        let p = hash_to_fr::<1>(&[dst, data].concat())[0];
        p.into()
    }
}

impl FrostCurve for BabyJubJub {
    const CONTEXT: &'static [u8] = b"FROST-BabyJubJub-Blake2b-v1";
}
