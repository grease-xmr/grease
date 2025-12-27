use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::BabyJubJubParams;
use std::hash::poseidon2_permutation;

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
    let input: [Field; 4] = [
        library::HASH_HEADER_CONSTANT_UPDATE_0,
        witness_im1,
        library::HASH_HEADER_CONSTANT_UPDATE_1,
        library::HASH_HEADER_CONSTANT_UPDATE_2,
    ];
    let output: [Field; 4] = poseidon2_permutation(input, input.len());
    let hash = output[0];
    let hash_bignum: U256 = U256::from(hash);

    //Clamp to Baby Jubjub order [251 bit value]
    let l_bignum: U256 = U256::from(library::BABY_JUBJUB_ORDER);

    let value_bignum = hash_bignum.umod(l_bignum);
    let mut value_field: Field = bignum::bignum::to_field(value_bignum) as Field;
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
    response_BabyJubJub: [u8; 32],
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
        response_ed25519,
    );
}
