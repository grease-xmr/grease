//!  The prime field GF(r) where r is the order of the cryptographic subgroup. For BabyJubJub,
//!         r = ℓ = 2736030358979909402780800718157159386076813972158567259200215660948447373041 (251 bits)
//!  It contains scalars for point multiplication (k·P operations) and defines the space of valid private keys.
//!  Security depends on the discrete logarithm problem in this field.
//!  The full curve group has order n = h·r where h = 8 (the cofactor) and r is the largest prime factor of n.

use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "2736030358979909402780800718157159386076813972158567259200215660948447373041"]
#[generator = "31"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;
