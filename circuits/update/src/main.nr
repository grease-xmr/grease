use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
use std::{hash::blake2s, ops::Mul};
use dep::bignum::fields::U512::U512;

// This is the constant for VCOF hashing
global HASH_HEADER_CONSTANT: [u8; 32] = [0; 32];//TODO: Create a domain-separation constant

/// Verify COF [given VerifyWitness0() at initialization]
fn VerifyCOF(
    T_im1: edwards::Curve<BabyJubJubParams>,
    T_i: edwards::Curve<BabyJubJubParams>,
    witness_im1: Field,
    witness_i: Field,
) {
    library::VerifyTi(T_im1, witness_im1);
    library::VerifyTi(T_i, witness_i);

    //Create hash (random oracle) from previous entropy
    let constant_slice: [u8] = HASH_HEADER_CONSTANT.as_slice();
    let witness_im1_array: [u8; 32] = witness_im1.to_be_bytes();
    let pre_image_slice: [u8] = constant_slice.append(witness_im1_array);
    let pre_image_array: [u8; 64] = pre_image_slice.as_array();
    let hash_bytes: [u8; 32] = blake2s(pre_image_array);
    let hash_bytes_slice: [u8] = hash_bytes.as_slice();
    // U256 from_be_bytes expects 32 bytes + 1 byte for potential overflow
    // We add a leading 0u8 since our data won't use the full 256-bit range and is ignored in the modulo
    let hash_bytes_33: [u8] = &[0].append(hash_bytes_slice);
    let hash_bignum: U256 = U256::from_be_bytes(hash_bytes_33.as_array());

    //Clamp to Baby Jubjub order [251 bit value]
    let l_bignum: U256 = U256::from(library::BABY_JUBJUB_ORDER);

    let value_bignum = hash_bignum.umod(l_bignum);
    let mut value_field = bignum::bignum::to_field(value_bignum);
    if value_field == 0 {
        value_field = library::BABY_JUBJUB_ORDER;
    }

    assert_eq(value_field, witness_i);
}

/// Main function for update
fn main(
    T_im1: pub edwards::Curve<BabyJubJubParams>,
    T_i: pub edwards::Curve<BabyJubJubParams>,
    witness_im1: Field,
    witness_i: Field,
    challenge_bytes: pub [u8; 32],
    blinding_DLEQ: Field,
    response_div_BabyJubJub: [u8; 32],
    response_BabyJubJub: Field,
    response_div_ed25519: [u8; 32],
    response_ed25519: [u8; 32],
) {
    VerifyCOF(T_im1, T_i, witness_im1, witness_i);

    library::VerifyEquivalentModulo(
        challenge_bytes,
        blinding_DLEQ,
        witness_i,
        response_div_BabyJubJub,
        response_BabyJubJub,
        response_div_ed25519,
        response_ed25519
    );
}
