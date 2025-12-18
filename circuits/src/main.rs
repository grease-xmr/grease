use serde::{Deserialize, Serialize};
// use babyjubjub_rs::*;
use num_bigint::{BigInt, BigUint};
// use babyjubjub_rs::{Fr, constants::*};
use grease_babyjubjub::{BabyJubJub, Point};
// use babyjubjub_rs::Point;
use std::ops::Mul;
use grease_babyjubjub::SUBORDER_BJJ;
use circuits::generate_initial_proofs;
use circuits::helpers::byte_array_to_string_array;
use std::io;
use std::path::PathBuf;
use ark_ff::{AdditiveGroup, BigInteger, FftField, Field, One, PrimeField, Zero};
use ark_std::rand::RngCore;
// use ff::Field;
// use primeorder::Field;
use group::ff::{Field as SeraiField, FieldBits, PrimeField as SeraiPrimeField, PrimeFieldBits};

#[derive(Serialize)]
struct PointConfig {
    x: String,
    y: String,
}
impl From<&Point> for PointConfig {
    fn from(p: &Point) -> Self {
        PointConfig { x: p.x.to_string(), y: p.y.to_string() }
    }
}
impl From<Point> for PointConfig {
    fn from(p: Point) -> Self {
        PointConfig { x: p.x.to_string(), y: p.y.to_string() }
    }
}

#[expect(non_snake_case)]
#[derive(Serialize)]
struct InitConfig {
    blinding: String,
    blinding_DLEQ: String,
    challenge_bytes: [String; 32],
    enc_2: String,
    nonce_peer: String,
    r_2: String,
    response_div_BabyJubJub: [String; 32],
    response_div_ed25519: [String; 32],
    response_BabyJubJub: String,
    response_ed25519: [String; 32],
    witness_0: String,

    T_0: PointConfig,
    fi_2: PointConfig,
    pubkey_KES: PointConfig,
}

fn get_point_config_baby_jubjub(point: &Point) -> PointConfig {
    //Fr(0x1975e7e9cbe0f2ed7a06a09e320036ea1a73862ee2614d2a9a6452d8f7c9aff0)
    let x: String = point.x.to_string();
    assert!(x.len() == 70, "get_field_bytes: field is not correctly self-describing");
    let x_str = &x[3..69];

    let y: String = point.y.to_string();
    assert!(y.len() == 70, "get_field_bytes: field is not correctly self-describing");
    let y_str = &y[3..69];

    PointConfig { x: x_str.to_string(), y: y_str.to_string() }
}

fn main() {
    println!("Writing init/Prover.toml");

    // let mut rng = rand::thread_rng();
    let mut rng = ark_std::test_rng();

    // let BABY_JUBJUB_ORDER = BigUint::("2736030358979909402780800718157159386076813972158567259200215660948447373041");

    // //Settings - External
    // const nonce_peer = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    let nonce_peer: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    // const privateKey_KES = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    // let privateKey_KES: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());
    let privateKey_KES = grease_babyjubjub::Scalar::random(&mut rng);

    //Settings - Internal
    // const blinding = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    let blinding: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());
    // const r_2 = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    // let r_2 = grease_babyjubjub::Scalar::random(&mut rng);
    let r_2: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    // const blinding_DLEQ_Init = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    let blinding_DLEQ_Init: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());
    // const blinding_DLEQ_Update = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
    let blinding_DLEQ_Update: BigUint = num_bigint::RandBigInt::gen_biguint_below(&mut rng, &SUBORDER_BJJ.try_into().unwrap());

    //Derives
    // const pubkey_KES = mulPointEscalar(Base8, privateKey_KES);
    let bjj_gen = grease_babyjubjub::generators();
    let pubkey_KES = bjj_gen[0].mul(&privateKey_KES);

    let initial_proof = generate_initial_proofs(
        &nonce_peer,
        &blinding,
        &r_2,
        &pubkey_KES.into(),
        &blinding_DLEQ_Init,
    ).unwrap();

    // // const hash_VerifyWitness0_array = poseidon.permute([1, nonce_peer, blinding, 1])
    // // const hash_VerifyWitness0 = hash_VerifyWitness0_array[0];
    // // var witness_0 = hash_VerifyWitness0 % BABY_JUBJUB_ORDER;
    // // if (witness_0 == 0) witness_0 = BABY_JUBJUB_ORDER;
    // let one_fr: Fr = Fr::from_str("1").unwrap();
    // let mut big_arr: Vec<Fr> = Vec::new();
    // big_arr.push(one_fr.clone());
    // big_arr.push(Fr::from_str(&nonce_peer.to_string()).unwrap());
    // big_arr.push(Fr::from_str(&blinding.to_string()).unwrap());
    // big_arr.push(one_fr);
    // let poseidon = Poseidon::new();
    // let hash_VerifyWitness0 = poseidon.hash(big_arr).unwrap();
    // let hash_VerifyWitness0_BigUint: BigUint = hash_VerifyWitness0.to_string().parse().unwrap();
    // let mut witness_0: BigUint = hash_VerifyWitness0_BigUint % SUBORDER_BJJ.into();
    // if witness_0 == BigUint::from(0) { 
    //     witness_0 = SUBORDER_BJJ.into();
    // }
    // let t_0 = bjj_gen[0].mul(witness_0.into());

    let config: InitConfig = InitConfig {
        blinding: blinding.to_string(),
        blinding_DLEQ: blinding_DLEQ_Init.to_string(),
        challenge_bytes: byte_array_to_string_array(&initial_proof.challenge_bytes),
        enc_2: initial_proof.enc_2.to_string(),
        nonce_peer: nonce_peer.to_string(),
        r_2: r_2.to_string(),
        response_div_BabyJubJub: byte_array_to_string_array(&initial_proof.response_div_baby_jub_jub),
        response_div_ed25519: byte_array_to_string_array(&initial_proof.response_div_ed25519),
        response_BabyJubJub: initial_proof.r1.to_string(),
        response_ed25519: byte_array_to_string_array(&initial_proof.r2),
        witness_0: initial_proof.witness_0.to_string(),

        T_0: initial_proof.t_0.into(),
        fi_2: initial_proof.phi_2.into(),
        pubkey_KES: pubkey_KES.into(),
    };

    // Serialize to TOML string
    let toml_string = toml::to_string_pretty(&config).map_err(io::Error::other).unwrap();
    let target_path = PathBuf::from("../circuits/init");

    let witness_config_path = target_path.join("Prover.toml");
    let witness_config_filename = format!("{}", witness_config_path.display());

    std::fs::write(&witness_config_path, &toml_string).unwrap();

    println!("Writing update/Prover.toml");

}