use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::{EdwardsPoint, Scalar};
use digest::Digest;

pub trait HashToScalar: Default {
    type Scalar;
    fn hash_to_scalar<B: AsRef<[u8]>>(&mut self, input: B) -> Self::Scalar;
}

pub trait HashToPoint: Default {
    type Point;
    fn hash_to_point<B: AsRef<[u8]>>(&mut self, input: B) -> Self::Point;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Blake512;

impl HashToScalar for Blake512 {
    type Scalar = Scalar;
    fn hash_to_scalar<B: AsRef<[u8]>>(&mut self, input: B) -> Self::Scalar {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(input.as_ref());
        let mut result = [0u8; 64];
        result.copy_from_slice(hasher.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&result)
    }
}

impl HashToPoint for Blake512 {
    type Point = EdwardsPoint;
    fn hash_to_point<B: AsRef<[u8]>>(&mut self, input: B) -> Self::Point {
        let mut hasher = blake2::Blake2b512::new();
        hasher.update(input.as_ref());
        let mut result = [0u8; 64];
        result.copy_from_slice(hasher.finalize().as_slice());
        let scalar = Scalar::from_bytes_mod_order_wide(&result);
        &scalar * ED25519_BASEPOINT_TABLE
    }
}
