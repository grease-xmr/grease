use circuits::helpers::*;
use circuits::InitConfig;
use circuits::UpdateConfig;
use circuits::{generate_initial_proofs, generate_update};
use grease_babyjubjub::Scalar;
use grease_babyjubjub::SUBORDER_BJJ;
use num_bigint::BigUint;
use std::io;
use std::ops::Mul;
use std::path::PathBuf;

fn main() {
    let mut rng = ark_std::test_rng();

    //Settings - External
    let nonce_peer: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());
    let private_key_kes: Scalar = Scalar::from(BigUint::from(1u16));

    //Settings - Internal
    let blinding: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());
    let r_2: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    let blinding_dleq_init: BigUint =
        num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    let blinding_dleq_update: BigUint =
        num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    //Derives
    let bjj_gen = grease_babyjubjub::generators();
    let pubkey_kes = bjj_gen[0].mul(&private_key_kes);

    //Init
    println!("Writing init/Prover.toml");
    let initial_proof =
        generate_initial_proofs(&nonce_peer, &blinding, &r_2, &pubkey_kes.into(), &blinding_dleq_init).unwrap();

    let config: InitConfig = InitConfig {
        blinding: blinding.to_string(),
        blinding_DLEQ: blinding_dleq_init.to_string(),
        challenge_bytes: byte_array_to_string_array(&initial_proof.challenge_bytes),
        enc_2: initial_proof.enc_2.to_string(),
        nonce_peer: nonce_peer.to_string(),
        r_2: r_2.to_string(),
        response_div_BabyJubJub: byte_array_to_string_array(&initial_proof.response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&initial_proof.response_div_ed25519),
        response_BabyJubJub: byte_array_to_string_array(
            &left_pad_bytes_32(&initial_proof.rho_bjj.to_bytes_be()).unwrap(),
        ),
        response_ed25519: byte_array_to_string_array(&left_pad_bytes_32(&initial_proof.rho_ed.to_bytes_be()).unwrap()),
        witness_0: initial_proof.witness_0.to_string(),

        T_0: initial_proof.t_0.into(),
        fi_2: initial_proof.phi_2.into(),
        pubkey_KES: pubkey_kes.into(),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(io::Error::other).unwrap();
    let target_path = PathBuf::from("../circuits/init");

    let witness_config_path = target_path.join("Prover.toml");

    std::fs::write(&witness_config_path, &toml_string).unwrap();

    //Update
    println!("Writing update/Prover.toml");
    let update_proof = generate_update(&initial_proof.witness_0, &blinding_dleq_update, &initial_proof.t_0).unwrap();

    let config: UpdateConfig = UpdateConfig {
        blinding_DLEQ: blinding_dleq_update.to_string(),
        challenge_bytes: byte_array_to_string_array(&update_proof.challenge_bytes),
        response_div_BabyJubJub: byte_array_to_string_array(&update_proof.response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&update_proof.response_div_ed25519),
        response_BabyJubJub: byte_array_to_string_array(
            &left_pad_bytes_32(&update_proof.rho_bjj.to_bytes_be()).unwrap(),
        ),
        response_ed25519: byte_array_to_string_array(&left_pad_bytes_32(&update_proof.rho_ed.to_bytes_be()).unwrap()),
        witness_i: update_proof.witness_i.to_string(),
        witness_im1: initial_proof.witness_0.to_string(),

        T_i: update_proof.t_current.into(),
        T_im1: initial_proof.t_0.into(),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(io::Error::other).unwrap();
    let target_path = PathBuf::from("../circuits/update");

    let witness_config_path = target_path.join("Prover.toml");

    std::fs::write(&witness_config_path, &toml_string).unwrap();
}
