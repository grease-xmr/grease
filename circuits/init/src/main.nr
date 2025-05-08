use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
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
    assert_lt(nonce_peer, library::L);
    assert_lt(witness_0, library::L);
    assert_lt(blinding, library::L);

    library::VerifyTi(T_0, witness_0);

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
    let l_bignum: U256 = U256::from(library::L);

    let witness_0_calc_bignum = hash_bignum.umod(l_bignum);
    let witness_0_calc_field = bignum::bignum::to_field(witness_0_calc_bignum);

    assert_lt(witness_0_calc_field, library::L); //TODO: Is this necessary since the function has already been calculated?
    // Ensure the witness matches the reduced hash
    assert_eq(witness_0_calc_field, witness_0);
}

/// Verify protocol conformance of using the Feldman 2-of-2 Verifiable Secret Share on `witness_0` and encryption of shares to peer and KES [given VerifyWitness0()]
fn VerifyWitnessSharing(
    witness_0: Field,
    a_1: Field,
    c_0: edwards::Curve<BabyJubJubParams>,
    c_1: edwards::Curve<BabyJubJubParams>,
    fi_1: edwards::Curve<BabyJubJubParams>,
    enc_1: edwards::Curve<BabyJubJubParams>,
    share_1: Field,
    r_1: Field,
    pubkey_peer: edwards::Curve<BabyJubJubParams>,
    fi_2: edwards::Curve<BabyJubJubParams>,
    enc_2: edwards::Curve<BabyJubJubParams>,
    share_2: Field,
    r_2: Field,
    pubkey_KES: edwards::Curve<BabyJubJubParams>,
) {
    // Given: VerifyWitness0(nonce_peer, T_0, witness_0, blinding);

    //Produce VSS values
    let (c_1_calc, share_1_calc, share_2_calc) =
        library::FeldmanSecretShare_2_of_2_Optimized(witness_0, a_1);
    assert_eq(c_1_calc, c_1);
    assert_eq(share_1_calc, share_1);
    assert_eq(share_2_calc, share_2);

    //Encrypt to peer
    let (fi_1_calc, enc_1_calc) = library::encrypt_message(share_1, r_1, pubkey_peer);
    assert_eq(fi_1_calc, fi_1);
    assert_eq(enc_1_calc, enc_1);

    //Encrypt to KES
    let (fi_2_calc, enc_2_calc) = library::encrypt_message(share_2, r_2, pubkey_KES);
    assert_eq(fi_2_calc, fi_2);
    assert_eq(enc_2_calc, enc_2);
}

/// Main function for initialization
fn main(
    nonce_peer: pub Field,
    T_0: pub edwards::Curve<BabyJubJubParams>,
    witness_0: Field,
    blinding: Field,
    a_1: Field,
    c_0: pub edwards::Curve<BabyJubJubParams>,
    c_1: pub edwards::Curve<BabyJubJubParams>,
    fi_1: edwards::Curve<BabyJubJubParams>,
    enc_1: edwards::Curve<BabyJubJubParams>,
    share_1: Field,
    r_1: Field,
    pubkey_peer: pub edwards::Curve<BabyJubJubParams>,
    fi_2: edwards::Curve<BabyJubJubParams>,
    enc_2: edwards::Curve<BabyJubJubParams>,
    share_2: Field,
    r_2: Field,
    pubkey_KES: pub edwards::Curve<BabyJubJubParams>,
) {
    VerifyWitness0(nonce_peer, T_0, witness_0, blinding);

    VerifyWitnessSharing(
        witness_0,
        a_1,
        c_0,
        c_1,
        fi_1,
        enc_1,
        share_1,
        r_1,
        pubkey_peer,
        fi_2,
        enc_2,
        share_2,
        r_2,
        pubkey_KES,
    );
}
