use dep::bignum;
use dep::bignum::BigNum;
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
use edwards::scalar_field::ScalarField;
use std::field::bn254::assert_lt;

// Generator point of Baby Jubjub curve.
// ref: https://github.com/noir-lang/noir-edwards/blob/main/src/test.nr#L6C8-L6C13
global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

global generator: Curve<BabyJubJubParams> = BabyJubJub::from((BASE8[0], BASE8[1]));

// Baby Jubjub curve order [251 bit value]
pub global L: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

/// Creates a Baby Jubjub point from a scalar, specifically a Baby Jubjub public key from a secret scalar.
pub fn field_scalar_to_point(value: Field) -> edwards::Curve<BabyJubJubParams> {
    // Ensure value < l.
    assert_lt(value, L);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since value is already known to be max 251 bits, there are 63 slices.
    let value_scalar: ScalarField<63> = ScalarField::from(value);
    let point = generator.mul(value_scalar);

    point
}

/// Encrypts a field to a Baby Jubjub public key using EC ElGamal encryption.
pub fn encrypt_message(
    message: Field,
    r: Field,
    pubkey: edwards::Curve<BabyJubJubParams>,
) -> (edwards::Curve<BabyJubJubParams>, edwards::Curve<BabyJubJubParams>) {
    // Ensure 0 < r < l.
    assert(r != 0);
    assert_lt(r, L);

    // Ephemeral public key = r * G (G is the generator)
    let ephemeral = field_scalar_to_point(r);

    // Convert the randomness to Scalar
    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since r is already known to be max 251 bits, there are 63 slices.
    let r_scalar: ScalarField<63> = ScalarField::from(r);

    // Shared secret = r * pubkey
    let shared_secret = pubkey.mul(r_scalar);

    // Message encoding = m * G
    let message_point = field_scalar_to_point(message);

    // Encrypted message = msg_point + shared_secret
    let cipher = message_point + shared_secret;

    // Output both parts of the ciphertext
    (ephemeral, cipher)
}

/// Verify T_i [given previous VerifyCOF() and original VerifyWitness0()]
pub fn VerifyTi(T_i: edwards::Curve<BabyJubJubParams>, witness_i: Field) {
    //Produce statement point
    let public_key: Curve<BabyJubJubParams> = field_scalar_to_point(witness_i);
    assert_eq(public_key, T_i);
}

/// Verify Feldman Secret Share is correct for all parameters and shares [given `secret` and `a_1`]
pub fn FeldmanSecretShare_2_of_2(
    secret: Field,
    a_1: Field,
) -> (Curve<BabyJubJubParams>, Curve<BabyJubJubParams>, Field, Field) {
    // Ensure secret < l.
    assert_lt(secret, L);
    // Ensure a_1 < l.
    assert_lt(a_1, L);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since secret is already known to be max 251 bits, there are 63 slices.
    let secret_scalar: ScalarField<63> = ScalarField::from(secret);
    let c_0 = generator.mul(secret_scalar);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since a_1 is already known to be max 251 bits, there are 63 slices.
    let a_1_scalar: ScalarField<63> = ScalarField::from(a_1);
    let c_1: Curve<BabyJubJubParams> = generator.mul(a_1_scalar);

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(L);

    let share_1_calc: Field = secret + a_1;
    let share_1_calc_bignum = U256::from(share_1_calc);
    let share_1_calc_mod_bignum = share_1_calc_bignum.umod(l_bignum);
    let share_1_calc_mod_field = bignum::bignum::to_field(share_1_calc_mod_bignum);

    // Calculate share_2 = secret + 2*a_1 by adding a_1 to share_1
    let share_2_calc = share_1_calc + a_1;
    let share_2_calc_bignum = U256::from(share_2_calc);
    let share_2_calc_mod_bignum = share_2_calc_bignum.umod(l_bignum);
    let share_2_calc_mod_field = bignum::bignum::to_field(share_2_calc_mod_bignum);

    (c_0, c_1, share_1_calc_mod_field, share_2_calc_mod_field)
}

/// Verify Feldman Secret Share is correct for all parameters and shares [given `secret` and `a_1`]
pub fn FeldmanSecretShare_2_of_2_Optimized(
    secret: Field,
    a_1: Field,
) -> (Curve<BabyJubJubParams>, Field, Field) {
    // Given 0 < secret < l.
    // Ensure a_1 < l.
    assert_lt(a_1, L);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since a_1 is already known to be max 251 bits, there are 63 slices.
    let a_1_scalar: ScalarField<63> = ScalarField::from(a_1);
    let c_1: Curve<BabyJubJubParams> = generator.mul(a_1_scalar);

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(L);

    let share_1_calc: Field = secret + a_1;
    let share_1_calc_bignum = U256::from(share_1_calc);
    let share_1_calc_mod_bignum = share_1_calc_bignum.umod(l_bignum);
    let share_1_calc_mod_field = bignum::bignum::to_field(share_1_calc_mod_bignum);

    // Calculate share_2 = secret + 2*a_1 by adding a_1 to share_1
    let share_2_calc = share_1_calc + a_1;
    let share_2_calc_bignum = U256::from(share_2_calc);
    let share_2_calc_mod_bignum = share_2_calc_bignum.umod(l_bignum);
    let share_2_calc_mod_field = bignum::bignum::to_field(share_2_calc_mod_bignum);

    (c_1, share_1_calc_mod_field, share_2_calc_mod_field)
}
