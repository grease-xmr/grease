use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJubParams};
use std::field::bn254::assert_lt;
use std::hash::blake2s;

// This is the constant for VerifyWitness0 hashing
global HASH_HEADER_CONSTANT: [u8; 32] = [0; 32]; //TODO: Create a domain-separation constant

/// Verify witness_0 [no given]
fn VerifyWitness0(
    nonce_peer: Field,
    T_0: edwards::Curve<BabyJubJubParams>,
    witness_0: Field,
    blinding: Field,
) {
    assert(nonce_peer != 0);
    assert(witness_0 != 0);
    assert(blinding != 0);
    assert_lt(nonce_peer, library::BABY_JUBJUB_ORDER_PLUS_ONE);
    assert_lt(witness_0, library::BABY_JUBJUB_ORDER_PLUS_ONE);
    assert_lt(blinding, library::BABY_JUBJUB_ORDER_PLUS_ONE);

    //Create hash (random oracle) from both peers' entropy to ensure uniqueness
    let constant_slice: [u8] = HASH_HEADER_CONSTANT.as_slice();
    let nonce_peer_array: [u8; 32] = nonce_peer.to_be_bytes();
    let blinding_array: [u8; 32] = blinding.to_be_bytes();

    let pre_image_slice: [u8] = constant_slice.append(nonce_peer_array).append(blinding_array);
    let pre_image_array: [u8; 96] = pre_image_slice.as_array();
    let hash_bytes: [u8; 32] = blake2s(pre_image_array);
    let hash_bytes_slice: [u8] = hash_bytes.as_slice();
    // U256 from_be_bytes expects 32 bytes + 1 byte for potential overflow
    // We add a leading 0u8 since our data won't use the full 256-bit range and is ignored in the modulo
    let hash_bytes_33: [u8] = &[0].append(hash_bytes_slice);
    let hash_bignum: U256 = U256::from_be_bytes(hash_bytes_33.as_array());

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(library::BABY_JUBJUB_ORDER);

    let witness_0_calc_bignum = hash_bignum.umod(l_bignum);
    let mut witness_0_calc_field = bignum::bignum::to_field(witness_0_calc_bignum);
    if witness_0_calc_field == 0 {
        witness_0_calc_field = library::BABY_JUBJUB_ORDER;
    }

    assert_lt(witness_0_calc_field, library::BABY_JUBJUB_ORDER_PLUS_ONE); //TODO: Is this necessary since the function has already been calculated?
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
    response_BabyJubJub: Field,
    response_div_ed25519: [u8; 32],
    response_ed25519: [u8; 32],
) {
    VerifyWitness0(nonce_peer, T_0, witness_0, blinding);

    EncryptToKES(
        witness_0,
        fi_2,
        enc_2,
        r_2,
        pubkey_KES,
    );

    library::VerifyEquivalentModulo(
        challenge_bytes,
        blinding_DLEQ,
        witness_0,
        response_div_BabyJubJub,
        response_BabyJubJub,
        response_div_ed25519,
        response_ed25519
    );
}
