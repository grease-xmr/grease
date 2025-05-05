use dep::bignum;
use dep::bignum::{BigNum, BigNumTrait};
use dep::bignum::fields::U256::U256;
use edwards::bjj::{BabyJubJub, BabyJubJubParams};
use edwards::Curve;
use edwards::CurveTrait;
use std::field::bn254::assert_lt;
use std::hash::pedersen_hash;

// This is the constant for VCOF hashing
global VCOF_CONSTANT: Field = 1;

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
    let hash_scalar: _ = pedersen_hash([VCOF_CONSTANT, witness_im1]);

    //Clamp to Baby Jubjub order
    let l_bignum: U256 = U256::from(library::L);

    let hash_bignum = U256::from(hash_scalar);
    let mod_bignum = hash_bignum.umod(l_bignum);
    let mod_field = bignum::bignum::to_field(mod_bignum);

    assert_eq(mod_field, witness_i); //TODO: Is this necessary since the function has already been calculated?

    //TODO: Ensure that this is not necessary since the above assertion covers this
    // //Produce statement point
    // let t_0_calc: Curve<BabyJubJubParams> = library::field_scalar_to_point(mod_field);
    // assert_eq(t_0_calc, T_i);
}

/// Main function for update
fn main(
    T_im1: pub edwards::Curve<BabyJubJubParams>,
    T_i: pub edwards::Curve<BabyJubJubParams>,
    witness_im1: Field,
    witness_i: Field,
) {
    VerifyCOF(T_im1, T_i, witness_im1, witness_i);
}
