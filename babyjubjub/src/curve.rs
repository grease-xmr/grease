use crate::{BjjPoint, Scalar};
use blake2::Blake2b512;
use ciphersuite::Ciphersuite;
use elliptic_curve::bigint::{CheckedAdd, Encoding, NonZero, U384};
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};
use group::Group;
use group::ff::{Field, PrimeField};
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
        // This method is adapted from Serai, which in turns follows
        // https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-hashing-to-a-finite-field

        // In order to perform this reduction securely, 64-byte numbers are sufficient.
        // First, convert the modulus to a 48-byte number
        // This is done by getting -1 as bytes, parsing it into a U384, and then adding back one
        let mut modulus = [0; 48];
        // The byte repr of scalars will be 32 little-endian bytes. Set the first 32 bytes of our 48-byte array
        // accordingly
        modulus[..32].copy_from_slice(&(Self::F::ZERO - Self::F::ONE).to_repr());
        // Use a checked_add + unwrap since this addition cannot fail (being a 32-byte value with 48-bytes of space)
        // While a non-panicking saturating_add/wrapping_add could be used, they'd likely be less performant
        let modulus = U384::from_be_slice(&modulus).checked_add(&U384::ONE).unwrap();
        let mut wide = U384::from_be_bytes({
            let mut bytes = [0; 48];
            ExpandMsgXmd::<Blake2b512>::expand_message(&[data], &[Self::ID, dst], 48).unwrap().fill_bytes(&mut bytes);
            bytes
        })
        .rem(&NonZero::new(modulus).unwrap())
        .to_be_bytes();

        // Now that this has been reduced back to a 32-byte value, grab the lower 32-bytes
        let mut array = [0u8; 32];
        array.copy_from_slice(&wide[..32]);
        let res = Scalar::from_repr(array).unwrap();
        // Zeroize the temp values
        wide.zeroize();
        array.zeroize();
        res
    }
}
