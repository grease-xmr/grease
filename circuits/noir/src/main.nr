// Import Pedersen commitment helper
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
use edwards::scalar_field::ScalarField;
use std::field::bn254::assert_lt;
use std::hash::pedersen_hash;

// Generator point of Baby Jubjub curve.
// ref: https://github.com/noir-lang/noir-edwards/blob/main/src/test.nr#L6C8-L6C13
global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

// Baby Jubjub curve order [251 bit value]
global L: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

// This is the constant for VCOF hashing
global VCOF_CONSTANT: Field = 1;

/// Creates a Baby Jubjub point from a scalar, specifically a Baby Jubjub public key from a secret scalar.
fn field_scalar_to_point(value: Field) -> edwards::Curve<BabyJubJubParams> {
    // Ensure value < l.
    assert_lt(value, L);

    let generator: Curve<BabyJubJubParams> = BabyJubJub::from((BASE8[0], BASE8[1]));

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since value is already known to be max 251 bits, there are 63 slices.
    let value_scalar: ScalarField<63> = ScalarField::from(value);
    let point = generator.mul(value_scalar);

    point
}

/// Encrypts a field to a Baby Jubjub public key using EC ElGamal encryption.
fn encrypt_message(
    message: Field,
    r: Field,
    pubkey: edwards::Curve<BabyJubJubParams>,
) -> (edwards::Curve<BabyJubJubParams>, edwards::Curve<BabyJubJubParams>) {
    // Ensure r < l.
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

/// Verify witness_0 [no given]
fn VerifyWitness0(
    nonce_peer: Field,
    witness_0_commitment: Field,
    witness_0: Field,
    blinding: Field,
) {
    assert(nonce_peer != 0);
    assert(witness_0 != 0);
    // assert(blinding != 0); //TODO: Add back in.
    assert_lt(witness_0, L);
    assert_lt(blinding, L);

    //TODO: Make the commitment the Pedersen hash of [witness_0, blinding] instead of the multiplication of them since we want hiding
    let hash = pedersen_hash([witness_0, nonce_peer * blinding]);
    assert_eq(hash, witness_0_commitment);
}

/// Verify Feldman Secret Share is correct for all parameters and shares [given `secret` and `a_1`]
fn FeldmanSecretShare_2_of_2(
    secret: Field,
    a_1: Field,
) -> (Curve<BabyJubJubParams>, Curve<BabyJubJubParams>, Field, Field) {
    // Ensure secret < l.
    assert_lt(secret, L);
    // Ensure a_1 < l.
    assert_lt(a_1, L);

    let generator: Curve<BabyJubJubParams> = BabyJubJub::from((BASE8[0], BASE8[1]));

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since secret is already known to be max 251 bits, there are 63 slices.
    let secret_scalar: ScalarField<63> = ScalarField::from(secret);
    let c_0 = generator.mul(secret_scalar);

    // ScalarField is parameterised by the number of 4-bit slices it contains.
    // Since a_1 is already known to be max 251 bits, there are 63 slices.
    let a_1_scalar: ScalarField<63> = ScalarField::from(a_1);
    let c_1: Curve<BabyJubJubParams> = generator.mul(a_1_scalar);

    let share_1: Field = secret + a_1;
    assert_lt(share_1, L);

    let share_2 = secret + (a_1 * 2);
    assert_lt(share_2, L);

    (c_0, c_1, share_1, share_2)
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
    // Given: VerifyWitness0(nonce_peer, witness_0_commitment, witness_0, blinding);

    let (c_0_calc, c_1_calc, share_1_calc, share_2_calc) =
        FeldmanSecretShare_2_of_2(witness_0, a_1);
    assert_eq(c_0_calc, c_0);
    assert_eq(c_1_calc, c_1);
    assert_eq(share_1_calc, share_1);
    assert_eq(share_2_calc, share_2);

    let (fi_1_calc, enc_1_calc) = encrypt_message(share_1, r_1, pubkey_peer);
    assert_eq(fi_1_calc, fi_1);
    assert_eq(enc_1_calc, enc_1);

    let (fi_2_calc, enc_2_calc) = encrypt_message(share_2, r_2, pubkey_KES);
    assert_eq(fi_2_calc, fi_2);
    assert_eq(enc_2_calc, enc_2);
}

/// Verify witness_i [given VerifyWitness0() at initialization, `blinding`]
fn VerifyWitnessi(witness_i_commitment: Field, witness_i: Field, blinding: Field) {
    assert(witness_i != 0);
    assert_lt(witness_i, L);

    let hash = pedersen_hash([witness_i, blinding]);
    assert_eq(hash, witness_i_commitment);
}

/// Verify COF [given VerifyWitness0() at initialization]
fn VerifCOF(
    witness_im1_commitment: Field,
    witness_i_commitment: Field,
    witness_im1: Field,
    witness_i: Field,
    blinding: Field,
) {
    assert(blinding != 0); //TODO: Is this necessary since it's already been verified?
    assert_lt(blinding, L); //TODO: Is this necessary since it's already been verified?

    VerifyWitnessi(witness_im1_commitment, witness_im1, blinding);
    VerifyWitnessi(witness_i_commitment, witness_i, blinding);

    let hash = pedersen_hash([VCOF_CONSTANT, witness_im1]);
    assert_eq(hash, witness_i);
}

/// Verify T_i [given VerifyWitnessi()]
fn VerifyTi(T_i: edwards::Curve<BabyJubJubParams>, witness_i: Field) {
    // Given: VerifyWitnessi(witness_i_commitment, witness_i, blinding);

    let public_key = field_scalar_to_point(witness_i);
    assert_eq(public_key, T_i);
}

/// Main function for initialization
fn main(
    nonce_peer: pub Field,
    witness_0_commitment: pub Field,
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
    VerifyWitness0(nonce_peer, witness_0_commitment, witness_0, blinding);

    VerifyTi(T_0, witness_0);

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
