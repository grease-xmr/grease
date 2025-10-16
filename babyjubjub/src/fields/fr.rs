//!  The prime field GF(r) where r is the order of the cryptographic subgroup. For BabyJubJub,
//!         r = ℓ = 2736030358979909402780800718157159386076813972158567259200215660948447373041 (251 bits)
//!  It contains scalars for point multiplication (k·P operations) and defines the space of valid private keys.
//!  Security depends on the discrete logarithm problem in this field.
//!  The full curve group has order n = h·r where h = 8 (the cofactor) and r is the largest prime factor of n.

use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use blake2::Blake2b512;

#[derive(MontConfig)]
#[modulus = "2736030358979909402780800718157159386076813972158567259200215660948447373041"]
#[generator = "31"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

pub const SEC_PARAM_FR: usize = 254; // Maximizes use of Blake512's output
type FrHasher = DefaultFieldHasher<Blake2b512, SEC_PARAM_FR>;

pub const FR_HASH_TO_FIELD_DOMAIN: &[u8] = b"BabyJubJub-FrH2F-ARK-v1";

pub fn hash_to_fr<const N: usize>(msg: &[u8]) -> [Fr; N] {
    let hasher = <FrHasher as HashToField<Fr>>::new(FR_HASH_TO_FIELD_DOMAIN);
    hasher.hash_to_field::<N>(msg)
}
