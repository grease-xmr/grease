//! The two `Ciphersuite` methods that `ciphersuite` 0.4.2 dropped when it split the trait into
//! `WrappedGroup` + `Id` + `WithPreferredHash` + `GroupCanonicalEncoding`.
//!
//! Both are reproduced here exactly as 0.4.1 defined them, because grease has frozen vectors and a
//! deterministic RNG stream riding on their behaviour.

use ciphersuite::group::ff::Field;
use ciphersuite::{WithPreferredHash, WrappedGroup};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

/// Hash `dst ‖ msg` to a scalar field element.
///
/// This is 0.4.1's `Ciphersuite::hash_to_F(dst, msg)`. That method was, for the dalek curves, literally
/// `Scalar::from_hash(Sha512(dst ‖ msg))`; 0.4.2's replacement `WithPreferredHash::hash_to_F(data)` is
/// `F::from_uniform_bytes(Sha512(data))`, and `from_uniform_bytes` on `curve25519_dalek::Scalar` *is*
/// `from_bytes_mod_order_wide`. Concatenating the domain tag here therefore reproduces the old output byte for
/// byte, which the PVSS, Schnorr PoK, adaptor-signature and ECDH vectors depend on.
#[allow(non_snake_case)]
pub fn hash_to_F<C: WithPreferredHash>(dst: &[u8], msg: &[u8]) -> C::F {
    C::hash_to_F([dst, msg].concat())
}

/// Draw a uniformly random non-zero scalar field element.
///
/// This is 0.4.1's `Ciphersuite::random_nonzero_F`, down to the rejection loop: one `Field::random` draw per
/// iteration, retrying only on zero. Anything else would shift the deterministic RNG streams grease derives
/// alongside it.
#[allow(non_snake_case)]
pub fn random_nonzero_F<C: WrappedGroup, R: RngCore + CryptoRng>(rng: &mut R) -> C::F {
    loop {
        let candidate = C::F::random(&mut *rng);
        if !bool::from(candidate.ct_eq(&C::F::ZERO)) {
            return candidate;
        }
    }
}
