const blake = require('blakejs')
const { Base8, mulPointEscalar, addPoint, packPoint, r, inCurve } = require( "@zk-kit/baby-jubjub")
const { ed25519 } = require('@noble/curves/ed25519');
const crypto = require('crypto');
const os = require('os');

//Constants
// Baby Jubjub curve order [251 bit value]
const BABY_JUBJUB_ORDER = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');
// Ed25519 curve order  [>252 bit value]
const ED25519_ORDER = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');
// BN254 curve order  [254 bit value]
const BN254_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
// Baby Jubjub prime order (alt_bn128)
const BABY_JUBJUB_PRIME = r;
// const BABY_JUBJUB_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

//Settings - External
const nonce_peer = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
const privateKey_KES = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;

//Settings - Internal
const blinding = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
const r_2 = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
const blinding_DLEQ_Init = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;
const blinding_DLEQ_Update = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;

//Derives
const pubkey_KES = mulPointEscalar(Base8, privateKey_KES);


function bigIntTo32ByteArray(bigInt) {
  // Ensure BigInt is non-negative and fits in 32 bytes
  if (bigInt < 0n) throw new Error('BigInt must be non-negative');
  if (bigInt >= 2n ** 256n) throw new Error('BigInt too large for 32 bytes');

  // Convert BigInt to hex string, remove '0x', and pad to 64 characters (32 bytes)
  const hex = bigInt.toString(16).padStart(64, '0');
  
  // Create a Buffer from the hex string
  const buffer = Buffer.from(hex, 'hex');
  
  // Return as Uint8Array (32 bytes)
  return new Uint8Array(buffer);
}

function bigIntTo32ByteArrayDecimal(bigInt) {
  // Ensure BigInt is non-negative and fits in 32 bytes
  if (bigInt < 0n) throw new Error('BigInt must be non-negative');
  if (bigInt >= 2n ** 256n) throw new Error('BigInt too large for 32 bytes');

  // Convert BigInt to hex string, remove '0x', and pad to 64 characters (32 bytes)
  const hex = bigInt.toString(16).padStart(64, '0');
  
  // Create a Buffer from the hex string
  const buffer = Buffer.from(hex, 'hex');
  
  // Uint8Array (32 bytes)
  const array = new Uint8Array(buffer);

  let output = '["';
  array.forEach((byte, index) => {
      output += byte.toString(10);
      if (index < array.length - 1) {
          output += '", "'; // Add comma separator except for the last byte
      }
  });
  output += '"]';

  return output;
}

function hexTo32ByteArrayDecimal(hexVariable) {
  // Pad to 64 characters (32 bytes)
  const hex = hexVariable.padStart(64, '0');

  // Create a Buffer from the hex string
  const buffer = Buffer.from(hex, 'hex');

  // Uint8Array (32 bytes)
  const array = new Uint8Array(buffer);

  let output = '[' + os.EOL;
  array.forEach((byte, index) => {
      output += '    "' + byte.toString(10) + '",' + os.EOL;
  });
  output += ']';

  return output;
}

/**
 * Subtract one point from another on the Baby Jubjub curve
 * @param {Point<bigint>} P - First point
 * @returns {Point<bigint>} Resulting point -P
 * @throws {Error} If point is not on the curve
 */
function negatePoint(P) {
    if (!inCurve(P)) {
        throw new Error('Point is not on the Baby Jubjub curve');
    }

    // Compute -P = (-x_P, y_P)
    const negP = [BABY_JUBJUB_PRIME - P[0], P[1]];

    return negP;
}

/**
 * Subtract one point from another on the Baby Jubjub curve
 * @param {Point<bigint>} P - First point
 * @param {Point<bigint>} Q - Second point to subtract
 * @returns {Point<bigint>} Resulting point P - Q
 * @throws {Error} If points are not on the curve
 */
function subtractPoint(P, Q) {
    if (!inCurve(P) || !inCurve(Q)) {
        throw new Error('Points are not on the Baby Jubjub curve');
    }

    // Compute -Q = (-x_Q, y_Q)
    const negQ = [BABY_JUBJUB_PRIME - Q[0], Q[1]];

    // Compute P + (-Q)
    return addPoint(P, negQ);
}

function generateDLEQProof_simple(secret, blinding_DLEQ) {
    if (secret <= 0n) throw new Error('secret must be positive');
    if (secret >= BABY_JUBJUB_ORDER) throw new Error('secret too large for Baby Jubjub');
    if (blinding_DLEQ <= 0n) throw new Error('blinding_DLEQ must be positive');
    if (blinding_DLEQ >= BABY_JUBJUB_ORDER) throw new Error('blinding_DLEQ too large for Baby Jubjub');

    //Baby Jubjub constants

    // Compute T = secret * G1 (Baby Jubjub)
    const T = mulPointEscalar(Base8, secret);

    //Ed25519 constants
    const g2 = ed25519.ExtendedPoint.BASE;

    // Compute S = secret * G2 (Ed25519)
    const S = g2.multiply(secret); // secret * G2

    // Compute commitments: R1 = blinding_DLEQ * G1 (Baby Jubjub)
    const R1 = mulPointEscalar(Base8, blinding_DLEQ);

    // Compute commitments: R2 = blinding_DLEQ * G2 (Ed25519)
    const R2 = g2.multiply(blinding_DLEQ);

    // Compute challenge c = H(HEADER, T, S, R1, R2)
    const challenge_preimage = Buffer.from([
        ...Array(32).fill(0x00), // NIZK_DLEQ HASH_HEADER_CONSTANT
        ...bigIntTo32ByteArray(packPoint(T)),
        ...S.toRawBytes(),
        ...bigIntTo32ByteArray(packPoint(R1)),
        ...R2.toRawBytes(),
    ]);
    const challenge_hash = blake.blake2sHex(challenge_preimage);
    const challenge_bigint = BigInt('0x' + challenge_hash); // Convert hex to BigInt

    // Compute response s = c * secret - blinding_DLEQ
    const response = (challenge_bigint * secret) - blinding_DLEQ;
    if (response <= 0n) throw new Error('s must be positive');

    const response_div_BabyJubJub = response / BABY_JUBJUB_ORDER;
    if (response_div_BabyJubJub >= (2n ** 256n)) throw new Error('response div BABY_JUBJUB_ORDER too large');

    const response_div_ed25519 = response / ED25519_ORDER;
    if (response_div_ed25519 >= (2n ** 256n)) throw new Error('response div ED25519_ORDER too large');

    // Compute response s = (c * secret - blinding_DLEQ) mod BABY_JUBJUB_ORDER
    const challenge_BabyJubJub = challenge_bigint % BABY_JUBJUB_ORDER;
    var response_BabyJubJub = (((challenge_BabyJubJub * secret) % BABY_JUBJUB_ORDER) - blinding_DLEQ) % BABY_JUBJUB_ORDER;
    if (response_BabyJubJub < 0n) {
      response_BabyJubJub += BABY_JUBJUB_ORDER;
    }
    if (response_BabyJubJub <= 0n) throw new Error('response on Baby Jubjub must be non-negative');
    if (response_BabyJubJub >= BABY_JUBJUB_ORDER) throw new Error('response too large for Baby Jubjub');

    if (response_BabyJubJub != response_BabyJubJub) throw new Error('response on Baby Jubjub error');

    // Compute response s = (c * secret - blinding_DLEQ) mod ED25519_ORDER
    const challenge_ed25519 = challenge_bigint % ED25519_ORDER;
    var response_ed25519 = (((challenge_ed25519 * secret) % ED25519_ORDER) - blinding_DLEQ) % ED25519_ORDER;
    if (response_ed25519 <= 0) {
        response_ed25519 += ED25519_ORDER;
    }
    if (response_ed25519 <= 0n) throw new Error('response on Ed25519 must be non-negative');
    if (response_ed25519 >= ED25519_ORDER) throw new Error('response too large for Ed25519');

    //Verify
    const response_BabyJubJub_g1 = mulPointEscalar(Base8, response_BabyJubJub);

    const response_BabyJubJub_g1_calc = mulPointEscalar(Base8, ((challenge_BabyJubJub * secret) - blinding_DLEQ) % BABY_JUBJUB_ORDER);
    if (response_BabyJubJub_g1_calc[0] != response_BabyJubJub_g1[0]) throw new Error('response_BabyJubJub_g1_calc != response_BabyJubJub_g1');
    if (response_BabyJubJub_g1_calc[1] != response_BabyJubJub_g1[1]) throw new Error('response_BabyJubJub_g1_calc != response_BabyJubJub_g1');

    const c_T = mulPointEscalar(T, challenge_BabyJubJub);

    const c_T_calc = mulPointEscalar(Base8, (challenge_BabyJubJub * secret) % BABY_JUBJUB_ORDER);
    if (c_T_calc[0] != c_T[0]) throw new Error('c_T_calc != c_T');
    if (c_T_calc[1] != c_T[1]) throw new Error('c_T_calc != c_T');

    const R1_calc = subtractPoint(c_T, response_BabyJubJub_g1);
    if (R1_calc[0] != R1[0]) throw new Error('R1_calc != R1');
    if (R1_calc[1] != R1[1]) throw new Error('R1_calc != R1');

    const response_ed25519_g2 = g2.multiply(response_ed25519);
    const c_S = S.multiply(challenge_ed25519);
    const R2_calc = c_S.subtract(response_ed25519_g2);
    if (R2_calc.equals(R2) == false) throw new Error('R2_calc != R2');

    //

    return {
        public: {
            T: packPoint(T).toString(16),
            S: S.toHex(),
        },
        proof: {
            challenge: challenge_hash,
            response_BabyJubJub: response_BabyJubJub.toString(16, 64),
            response_ed25519: response_ed25519.toString(16, 64),
        },
        commitments: {
            R1: packPoint(R1).toString(16),
            R2: R2.toHex(),
        },
        extra: {
            response_div_BabyJubJub: response_div_BabyJubJub.toString(16, 64),
            response_div_ed25519: response_div_ed25519.toString(16, 64),
        }
    };
}

//Init: VerifyWitness0 + Encrypt to KES

const byteArray_VerifyWitness0 = Buffer.from([
  ...Array(32).fill(0x00), // VerifyWitness0 HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(nonce_peer),
  ...bigIntTo32ByteArray(blinding),
]);
const hash_VerifyWitness0 = blake.blake2sHex(byteArray_VerifyWitness0);
const hashBig_VerifyWitness0 = BigInt('0x' + hash_VerifyWitness0); // Convert hex to BigInt

var witness_0 = hashBig_VerifyWitness0 % BABY_JUBJUB_ORDER;
if (witness_0 == 0) witness_0 = BABY_JUBJUB_ORDER;
let T_0 = mulPointEscalar(Base8, witness_0);

//Encrypt to KES
const ephemeral_2 = mulPointEscalar(Base8, r_2);
const rP_2 = mulPointEscalar(pubkey_KES, r_2);
const byteArray_2 = Buffer.from([
  ...bigIntTo32ByteArray(rP_2[0]),
  ...bigIntTo32ByteArray(rP_2[1]),
]);
const hash_2 = blake.blake2sHex(byteArray_2);
const hash_2Big = BigInt('0x' + hash_2); // Convert hex to BigInt
const shared_secret_2 = hash_2Big % BABY_JUBJUB_ORDER;
if (shared_secret_2 == 0) shared_secret_2 = BABY_JUBJUB_ORDER;
const cipher_2 = (witness_0 + shared_secret_2) % BABY_JUBJUB_ORDER;
if (cipher_2 == 0) cipher_2 = BABY_JUBJUB_ORDER;
const fi_2 = ephemeral_2;
const enc_2 = cipher_2;
//Verify
const fi_s_2 = mulPointEscalar(fi_2, privateKey_KES);
if (fi_s_2[0] != rP_2[0]) throw new Error('fi_s_2 != rP_2');
if (fi_s_2[1] != rP_2[1]) throw new Error('fi_s_2 != rP_2');
const byteArray_2_calc = Buffer.from([
  ...bigIntTo32ByteArray(fi_s_2[0]),
  ...bigIntTo32ByteArray(fi_s_2[1]),
]);
const hash_2_calc = blake.blake2sHex(byteArray_2_calc);
const hash_2Big_calc = BigInt('0x' + hash_2_calc); // Convert hex to BigInt
const shared_secret_2_calc = hash_2Big_calc % BABY_JUBJUB_ORDER;
if (shared_secret_2_calc == 0) shared_secret_2_calc = BABY_JUBJUB_ORDER;
var witness_0_calc = (enc_2 - shared_secret_2_calc) % BABY_JUBJUB_ORDER;
if (witness_0_calc <= 0n) {
  witness_0_calc += BABY_JUBJUB_ORDER;
}
if (witness_0_calc != witness_0) throw new Error('witness_0_calc != witness_0');

//NIZK DLEQ
const proof_Init = generateDLEQProof_simple(witness_0, blinding_DLEQ_Init);

console.log('Init: Ed25519 key S_0:', proof_Init.public.S);
console.log('Init: circuits/init/Prover.toml');
console.log('');
console.log(`blinding = "${blinding.toString()}"`);
console.log(`blinding_DLEQ = "${blinding_DLEQ_Init.toString()}"`);
console.log(`challenge_bytes = ${hexTo32ByteArrayDecimal(proof_Init.proof.challenge)}`);
console.log(`enc_2 = "${enc_2.toString()}"`);
console.log(`nonce_peer = "${nonce_peer.toString()}"`);
console.log(`r_2 = "${r_2.toString()}"`);
console.log(`response_div_BabyJubJub = ${hexTo32ByteArrayDecimal(proof_Init.extra.response_div_BabyJubJub).toString(10)}`);
console.log(`response_div_ed25519 = ${hexTo32ByteArrayDecimal(proof_Init.extra.response_div_ed25519).toString(10)}`);
console.log(`response_BabyJubJub = "${BigInt('0x' + proof_Init.proof.response_BabyJubJub).toString(10)}"`);
console.log(`response_ed25519 = ${hexTo32ByteArrayDecimal(proof_Init.proof.response_ed25519).toString(10)}`);
console.log(`witness_0 = "${witness_0.toString()}"`);

console.log('');
console.log('[T_0]');
console.log(`x="0x${T_0[0].toString(16).padStart(64, '0')}"`);
console.log(`y="0x${T_0[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[fi_2]');
console.log(`x="0x${fi_2[0].toString(16).padStart(64, '0')}"`);
console.log(`y="0x${fi_2[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[pubkey_KES]');
console.log(`x="0x${pubkey_KES[0].toString(16).padStart(64, '0')}"`);
console.log(`y="0x${pubkey_KES[1].toString(16).padStart(64, '0')}"`);

console.log('');
//Update/VerifyCOF
const byteArray = Buffer.from([
  ...Array(32).fill(0x00), // VCOF HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(witness_0),
]);
const hash = blake.blake2sHex(byteArray);
const hashBig = BigInt('0x' + hash); // Convert hex to BigInt
const witness_1 = hashBig % BABY_JUBJUB_ORDER;
if (witness_1 == 0) witness_1 = BABY_JUBJUB_ORDER;

const proof_Update = generateDLEQProof_simple(witness_1, blinding_DLEQ_Update);

console.log('Update: Ed25519 key S_i:', proof_Update.public.S);
console.log('Update: circuits/update/Prover.toml');
console.log('');
console.log(`blinding_DLEQ = "${blinding_DLEQ_Update.toString()}"`);
console.log(`challenge_bytes = ${hexTo32ByteArrayDecimal(proof_Update.proof.challenge)}`);
console.log(`response_div_BabyJubJub = ${hexTo32ByteArrayDecimal(proof_Update.extra.response_div_BabyJubJub).toString(10)}`);
console.log(`response_div_ed25519 = ${hexTo32ByteArrayDecimal(proof_Update.extra.response_div_ed25519).toString(10)}`);
console.log(`response_BabyJubJub = "${BigInt('0x' + proof_Update.proof.response_BabyJubJub).toString(10)}"`);
console.log(`response_ed25519 = ${hexTo32ByteArrayDecimal(proof_Update.proof.response_ed25519).toString(10)}`);
console.log(`witness_i = "${witness_1.toString()}"`);
console.log(`witness_im1 = "${witness_0.toString()}"`);

let T_i = mulPointEscalar(Base8, witness_1);

console.log('');
console.log('[T_i]');
console.log(`x="0x${T_i[0].toString(16).padStart(64, '0')}"`);
console.log(`y="0x${T_i[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[T_im1]');
console.log(`x="0x${T_0[0].toString(16).padStart(64, '0')}"`);
console.log(`y="0x${T_0[1].toString(16).padStart(64, '0')}"`);
