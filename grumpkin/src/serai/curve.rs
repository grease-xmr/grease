use crate::{GrumpkinPoint, Scalar, hash_to_fr};
use blake2::Blake2b512;
use ciphersuite::Ciphersuite;
use group::Group;
use modular_frost::curve::Curve as FrostCurve;
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Grumpkin;

impl Ciphersuite for Grumpkin {
    type F = Scalar;
    type G = GrumpkinPoint;
    type H = Blake2b512;

    const ID: &'static [u8] = b"Grumpkin-254-Blake2b-v1";

    fn generator() -> Self::G {
        GrumpkinPoint::generator()
    }

    #[allow(non_snake_case)]
    fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
        // hash_to_fr already uses proper DST, but we will mix in the dst here as well
        let p = hash_to_fr::<1>(&[dst, data].concat())[0];
        p.into()
    }
}

impl FrostCurve for Grumpkin {
    const CONTEXT: &'static [u8] = b"FROST-Grumpkin-Blake2b-v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::Field;

    #[test]
    fn ciphersuite_id() {
        assert_eq!(<Grumpkin as Ciphersuite>::ID, b"Grumpkin-254-Blake2b-v1");
    }

    #[test]
    fn ciphersuite_generator() {
        let g = <Grumpkin as Ciphersuite>::generator();
        assert_eq!(g, GrumpkinPoint::generator());
        assert!(!bool::from(g.is_identity()));
    }

    #[test]
    fn ciphersuite_hash_to_f_deterministic() {
        let dst = b"test-dst";
        let data = b"test-data";

        let h1 = <Grumpkin as Ciphersuite>::hash_to_F(dst, data);
        let h2 = <Grumpkin as Ciphersuite>::hash_to_F(dst, data);

        assert_eq!(h1, h2);
    }

    #[test]
    fn ciphersuite_hash_to_f_different_inputs() {
        let dst = b"test-dst";

        let h1 = <Grumpkin as Ciphersuite>::hash_to_F(dst, b"data1");
        let h2 = <Grumpkin as Ciphersuite>::hash_to_F(dst, b"data2");

        assert_ne!(h1, h2);
    }

    #[test]
    fn ciphersuite_hash_to_f_different_dst() {
        let data = b"test-data";

        let h1 = <Grumpkin as Ciphersuite>::hash_to_F(b"dst1", data);
        let h2 = <Grumpkin as Ciphersuite>::hash_to_F(b"dst2", data);

        assert_ne!(h1, h2);
    }

    #[test]
    fn ciphersuite_hash_to_f_not_zero() {
        // Hash should virtually never produce zero
        for i in 0..100 {
            let data = format!("test-data-{i}");
            let h = <Grumpkin as Ciphersuite>::hash_to_F(b"dst", data.as_bytes());
            assert_ne!(h, Scalar::ZERO);
        }
    }

    #[test]
    fn frost_curve_context() {
        assert_eq!(<Grumpkin as FrostCurve>::CONTEXT, b"FROST-Grumpkin-Blake2b-v1");
    }

    #[test]
    fn grumpkin_zeroize() {
        use zeroize::Zeroize;

        let mut g = Grumpkin;
        g.zeroize();
        // Grumpkin is a unit struct, zeroize is a no-op but should compile
        assert_eq!(g, Grumpkin);
    }

    #[test]
    fn grumpkin_clone_copy() {
        let g1 = Grumpkin;
        let g2 = g1;
        let g3 = g1.clone();
        assert_eq!(g1, g2);
        assert_eq!(g1, g3);
    }

    #[test]
    fn grumpkin_debug() {
        let g = Grumpkin;
        let debug_str = format!("{g:?}");
        assert_eq!(debug_str, "Grumpkin");
    }
}
