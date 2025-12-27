use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::BabyJubJubParams;
use std::field::bn254::assert_lt;
use std::hash::poseidon2_permutation;
use library::assert_valid_bjj_scalar_field;

/// Verify witness_0 [no given]
fn VerifyWitness0(
    nonce_peer: Field,
    T_0: edwards::Curve<BabyJubJubParams>,
    witness_0: Field,
    blinding: Field,
) {
    assert_valid_bjj_scalar_field(nonce_peer);
    assert_valid_bjj_scalar_field(witness_0);
    assert_valid_bjj_scalar_field(blinding);

    //Create hash (random oracle) from both peers' entropy to ensure uniqueness
    let input: [Field; 4] = [
        library::HASH_HEADER_CONSTANT_INIT_0,
        nonce_peer,
        blinding,
        library::HASH_HEADER_CONSTANT_INIT_1,
    ];
    let output: [Field; 4] = poseidon2_permutation(input, input.len());
    let hash = output[0];
    let hash_bignum: U256 = U256::from(hash);

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(library::BABY_JUBJUB_ORDER);

    let witness_0_calc_bignum = hash_bignum.umod(l_bignum);
    let mut witness_0_calc_field = bignum::bignum::to_field(witness_0_calc_bignum);
    if witness_0_calc_field == 0 {
        witness_0_calc_field = library::BABY_JUBJUB_ORDER;
    }

    // Ensure the witness matches the reduced hash
    assert_eq(witness_0_calc_field, witness_0);

    library::VerifyTi(T_0, witness_0);
}

/// Verify protocol conformance of encryption of `witness_0` to KES [given VerifyWitness0()]
fn EncryptToKES(
    witness_0: Field,
    fi_2: edwards::Curve<BabyJubJubParams>,
    enc_2: Field,
    r_2: Field,
    pubkey_KES: edwards::Curve<BabyJubJubParams>,
) {
    // Given: VerifyWitness0(nonce_peer, T_0, witness_0, blinding);

    //Encrypt to KES
    let (fi_2_calc, enc_2_calc) = library::VerifyEncryptMessage_ECDH(witness_0, r_2, pubkey_KES);
    assert_eq(fi_2_calc, fi_2);
    assert_eq(enc_2_calc, enc_2);
}

/// Main function for initialization
fn main(
    nonce_peer: pub Field,
    T_0: pub edwards::Curve<BabyJubJubParams>,
    witness_0: Field,
    blinding: Field,
    fi_2: edwards::Curve<BabyJubJubParams>,
    enc_2: Field,
    r_2: Field,
    pubkey_KES: pub edwards::Curve<BabyJubJubParams>,
    challenge_bytes: pub [u8; 32],
    blinding_DLEQ: Field,
    response_div_BabyJubJub: [u8; 32],
    response_BabyJubJub: [u8; 32],
    response_div_ed25519: [u8; 32],
    response_ed25519: [u8; 32],
) {
    VerifyWitness0(nonce_peer, T_0, witness_0, blinding);

    EncryptToKES(witness_0, fi_2, enc_2, r_2, pubkey_KES);

    library::VerifyEquivalentModulo(
        challenge_bytes,
        blinding_DLEQ,
        witness_0,
        response_div_BabyJubJub,
        response_BabyJubJub,
        response_div_ed25519,
        response_ed25519,
    );
}
