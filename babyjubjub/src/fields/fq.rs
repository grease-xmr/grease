//! The prime finite field GF(q) over which the curve is geometrically defined
//! For Baby Jubjub, q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//! and is 254 bits.

use ark_ff::fields::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "7"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;
