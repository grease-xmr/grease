//! The prime finite field GF(q) over which the curve is geometrically defined
//! For Baby Jubjub, q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! and is 254 bits.

use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use blake2::Blake2b512;

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "2"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

pub const SEC_PARAM_FQ: usize = 251; // Maximizes use of Blake512's output
pub(crate) type FqHasher = DefaultFieldHasher<Blake2b512, SEC_PARAM_FQ>;

pub const FQ_HASH_TO_FIELD_DOMAIN: &[u8] = b"BabyJubJub-FqH2F-ARK-v1";

pub fn hash_to_fq<const N: usize>(msg: &[u8]) -> [Fq; N] {
    let hasher = <FqHasher as HashToField<Fq>>::new(FQ_HASH_TO_FIELD_DOMAIN);
    hasher.hash_to_field::<N>(msg)
}
