use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
use edwards::scalar_field::ScalarField;
use std::field::bn254::assert_lt;
use dep::bignum::fields::U512::U512;
use std::{hash::blake2s, ops::Mul};

// Generator point of Baby Jubjub curve.
// ref: https://github.com/noir-lang/noir-edwards/blob/main/src/test.nr#L6C8-L6C13
global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

global generator: Curve<BabyJubJubParams> = BabyJubJub::from((BASE8[0], BASE8[1]));

// Baby Jubjub curve order [251 bit value]
pub global BABY_JUBJUB_ORDER: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
pub global BABY_JUBJUB_ORDER_PLUS_ONE: Field = BABY_JUBJUB_ORDER + 1;

/// Creates a Baby Jubjub point from a scalar, specifically a Baby Jubjub public key from a secret scalar.
pub fn field_scalar_to_point(value: Field) -> edwards::Curve<BabyJubJubParams> {
    // Ensure 0 < value <= l.
    assert(value != 0);
    assert_lt(value, BABY_JUBJUB_ORDER_PLUS_ONE);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since value is already known to be max 251 bits, there are 63 slices.
    let value_scalar: ScalarField<63> = ScalarField::from(value);
    let point = generator.mul(value_scalar);

    point
}

// /// Encrypts a field to a Baby Jubjub public key using EC ElGamal encryption.
// pub fn VerifyEncryptMessage_ElGamal(
//     message: Field,
//     r: Field,
//     pubkey: edwards::Curve<BabyJubJubParams>,
// ) -> (edwards::Curve<BabyJubJubParams>, edwards::Curve<BabyJubJubParams>) {
//     // Ensure 0 < r <= l.
//     assert(r != 0);
//     assert_lt(r, BABY_JUBJUB_ORDER_PLUS_ONE);
//     // Ensure 0 < message <= l.
//     assert(message != 0);
//     assert_lt(message, BABY_JUBJUB_ORDER_PLUS_ONE);

//     // Ephemeral public key = r * G (G is the generator)
//     let ephemeral = field_scalar_to_point(r);

//     // Convert the randomness to Scalar
//     // ScalarField is parameterised by the number of 4-bit slices it contains.
//     // Since r is already known to be max 251 bits, there are 63 slices.
//     let r_scalar: ScalarField<63> = ScalarField::from(r);

//     // Shared secret = r * pubkey
//     let shared_secret = pubkey.mul(r_scalar);

//     // Message encoding = m * G
//     let message_point = field_scalar_to_point(message);

//     // Encrypted message = msg_point + shared_secret
//     let cipher = message_point + shared_secret;

//     // Output both parts of the ciphertext
//     (ephemeral, cipher)
// }

/// Encrypts a field to a Baby Jubjub public key using ECDH encryption.
pub fn VerifyEncryptMessage_ECDH(
    message: Field,
    r: Field,
    pubkey: edwards::Curve<BabyJubJubParams>,
) -> (edwards::Curve<BabyJubJubParams>, Field) {
    // Ensure 0 < message <= l.
    assert(message != 0);
    assert_lt(message, BABY_JUBJUB_ORDER_PLUS_ONE);
    // Ensure 0 < r <= l.
    assert(r != 0);
    assert_lt(r, BABY_JUBJUB_ORDER_PLUS_ONE);

    // R = r * G (G is the generator)
    let R: Curve<BabyJubJubParams> = field_scalar_to_point(r);

    // Convert the randomness to Scalar
    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since r is already known to be max 251 bits, there are 63 slices.
    let r_scalar: ScalarField<63> = ScalarField::from(r);

    // Shared secret = H(r * pubkey)
    let rP = pubkey.mul(r_scalar);
    let rP_x: [u8; 32] = rP.x.to_be_bytes();
    let rP_y: [u8; 32] = rP.y.to_be_bytes();
    let pre_image_slice: [u8] = rP_x.as_slice().append(rP_y);
    let pre_image_array: [u8; 64] = pre_image_slice.as_array();
    let hash_bytes: [u8; 32] = blake2s(pre_image_array);
    let hash_bytes_slice: [u8] = hash_bytes.as_slice();
    // U256 from_be_bytes expects 32 bytes + 1 byte for potential overflow
    // We add a leading 0u8 since our data won't use the full 256-bit range and is ignored in the modulo
    let hash_bytes_33: [u8] = &[0].append(hash_bytes_slice);
    let hash_bignum: U256 = U256::from_be_bytes(hash_bytes_33.as_array());

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(BABY_JUBJUB_ORDER);

    let shared_secret_bignum: U256 = hash_bignum.umod(l_bignum);

    let message_bignum: U256 = U256::from(message);
    let cipher_bignum_over = shared_secret_bignum + message_bignum;
    let cipher_bignum: U256 = cipher_bignum_over.umod(l_bignum);
    let mut cipher: Field = bignum::bignum::to_field(cipher_bignum);
    if cipher == 0 {
        cipher = BABY_JUBJUB_ORDER;
    }

    (R, cipher)
}

/// Verify T_i [given previous VerifyCOF() and original VerifyWitness0()]
pub fn VerifyTi(T_i: edwards::Curve<BabyJubJubParams>, witness_i: Field) {
    //Produce statement point
    let public_key: Curve<BabyJubJubParams> = field_scalar_to_point(witness_i);
    assert_eq(public_key, T_i);
}

// /// Verify Feldman Secret Share is correct for all parameters and shares [given `secret` and `a_1`]
// pub fn FeldmanSecretShare_2_of_2_Optimized(
//     secret: Field,
//     a_1: Field,
// ) -> (Curve<BabyJubJubParams>, Field, Field) {
//     // Given 0 < secret <= l.
//     // Ensure 0 < a_1 <= l.
//     assert(a_1 != 0);
//     assert_lt(a_1, BABY_JUBJUB_ORDER_PLUS_ONE);

//     // ScalarField is parameterised by the number of 4-bit slices it contains.
//     // Since a_1 is already known to be max 251 bits, there are 63 slices.
//     let a_1_scalar: ScalarField<63> = ScalarField::from(a_1);
//     let c_1: Curve<BabyJubJubParams> = generator.mul(a_1_scalar);

//     //Clamp to Baby Jubjub order
//     let l_bignum: U256 = U256::from(BABY_JUBJUB_ORDER);

//     // let share_1_calc: Field = secret + a_1;
//     // let share_1_calc_bignum = U256::from(share_1_calc);
//     // let share_1_calc_mod_bignum = share_1_calc_bignum.umod(l_bignum);
//     // let share_1_calc_mod_field = bignum::bignum::to_field(share_1_calc_mod_bignum);

//     let secret_bignum: U256 = U256::from(secret);
//     let a_1_bignum: U256 = U256::from(a_1);

//     // Calculate share_1 = -(secret + a_1) = -secret - a_1
//     // Note: max(L - secret + L - a_1) = 2L - 2, min(L - secret + L - a_1) = 2
//     let mut share_1_calc: U256 = l_bignum - secret_bignum + l_bignum - a_1_bignum;
//     if (share_1_calc >= l_bignum)
//     {
//         share_1_calc -= l_bignum;
//     }
//     let share_1_calc_field = bignum::bignum::to_field(share_1_calc);

//     // // Calculate share_2 = secret + 2*a_1 by adding a_1 to share_1
//     // let share_2_calc = share_1_calc_mod_field + a_1;
//     // let share_2_calc_bignum = U256::from(share_2_calc);
//     // let share_2_calc_mod_bignum = share_2_calc_bignum.umod(l_bignum);
//     // let share_2_calc_mod_field = bignum::bignum::to_field(share_2_calc_mod_bignum);

//     // Calculate share_2 = 2*secret + a_1
//     // Note: max(secret + secret + a_1) = 3L - 3, min(secret + secret + a_1) = 3
//     let mut share_2_calc = secret_bignum + secret_bignum + a_1_bignum;
//     if (share_2_calc >= l_bignum)
//     {
//         share_2_calc -= l_bignum;

//         if (share_2_calc >= l_bignum)
//         {
//             share_2_calc -= l_bignum;
//         }
//     }

//     let share_2_calc_field = bignum::bignum::to_field(share_2_calc);

//     (c_1, share_1_calc_field, share_2_calc_field)
// }

// /// Verify Feldman Secret Share is correct for all parameters and shares [given `secret` and `a_1`]
// pub fn FeldmanSecretShare_2_of_2(
//     secret: Field,
//     a_1: Field,
// ) -> (Curve<BabyJubJubParams>, Curve<BabyJubJubParams>, Field, Field) {
//     // Ensure 0 < secret <= l.
//     assert(secret != 0);
//     assert_lt(secret, BABY_JUBJUB_ORDER_PLUS_ONE);
//     // Ensure 0 < a_1 <= l.
//     assert(a_1 != 0);
//     assert_lt(a_1, BABY_JUBJUB_ORDER_PLUS_ONE);

//     // ScalarField is parameterised by the number of 4-bit slices it contains.
//     // Since secret is already known to be max 251 bits, there are 63 slices.
//     let secret_scalar: ScalarField<63> = ScalarField::from(secret);
//     let c_0 = generator.mul(secret_scalar);

//     let (c_1, share_1_calc_mod_field, share_2_calc_mod_field) = FeldmanSecretShare_2_of_2_Optimized(secret, a_1);

//     (c_0, c_1, share_1_calc_mod_field, share_2_calc_mod_field)
// }

// // This is the constant for NIZK-DLEQ hashing
// global DLEQ_HASH_HEADER_CONSTANT: [u8; 32] = [0; 32];//TODO: Create a domain-separation constant

// Ed25519 curve order  [>252 bit value]
global ED25519_ORDER: Field = 7237005577332262213973186563042994240857116359379907606001950938285454250989;

pub fn VerifyEquivalentModulo(
    challenge_bytes: [u8; 32],
    blinding_DLEQ: Field,
    witness_i: Field,
    response_div_BabyJubJub: [u8; 32],
    response_BabyJubJub: Field,
    response_div_ed25519: [u8; 32],
    response_ed25519: [u8; 32],
) {
    // // challenge c = H(HEADER, T, S, R1, R2)
    let challenge_bytes_slice: [u8] = challenge_bytes.as_slice();

    // U512 from_be_bytes expects 64 bytes + 1 byte for potential overflow
    let challenge_bytes_65: [u8] = &[0; 33].append(challenge_bytes_slice);
    let challenge_U512: U512 = U512::from_be_bytes(challenge_bytes_65.as_array());

    //response = (challenge * secret) - blinding;
    let secret: U512 = U512::from(witness_i);
    let challenge_secret_calc: U512 = challenge_U512.mul(secret);

    let response_calc: U512 = challenge_secret_calc - U512::from(blinding_DLEQ);

    //Baby Jubjub order [251 bit value]
    let l_bignum: U512 = U512::from(BABY_JUBJUB_ORDER);

    // U512 from_be_bytes expects 64 bytes + 1 byte for potential overflow
    let response_div_BabyJubJub_bytes_65: [u8] = &[0; 33].append(response_div_BabyJubJub.as_slice());
    let response_div_BabyJubJub_bignum: U512 = U512::from_be_bytes(response_div_BabyJubJub_bytes_65.as_array());

    let response_BabyJubJub_bignum: U512 = U512::from(response_BabyJubJub);
    let response_calc_BabyJubJub = l_bignum.mul(response_div_BabyJubJub_bignum) + response_BabyJubJub_bignum;
    assert_eq(response_calc_BabyJubJub, response_calc);

    //Ed25519 order [>252 bit value]
    let ed25519_order_bignum: U512 = U512::from(ED25519_ORDER);

    // U512 from_be_bytes expects 64 bytes + 1 byte for potential overflow
    let response_div_ed25519_bytes_65: [u8] = &[0; 33].append(response_div_ed25519.as_slice());
    let response_div_ed25519_bignum: U512 = U512::from_be_bytes(response_div_ed25519_bytes_65.as_array());

    // U512 from_be_bytes expects 64 bytes + 1 byte for potential overflow
    let response_ed25519_bytes_65: [u8] = &[0; 33].append(response_ed25519.as_slice());
    let response_ed25519_bignum: U512 = U512::from_be_bytes(response_ed25519_bytes_65.as_array());

    let response_calc_ed25519 = ed25519_order_bignum.mul(response_div_ed25519_bignum) + response_ed25519_bignum;
    assert_eq(response_calc_ed25519, response_calc);
}
