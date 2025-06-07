const blake = require('blakejs')
const { Base8, mulPointEscalar, addPoint, packPoint, unpackPoint } = require( "@zk-kit/baby-jubjub")
// const ed25519 = require('ed25519');
const { ed25519 } = require('@noble/curves/ed25519');
// const { Point } = require('babyjubjub/lib/Point');
// const { FQ } = require('babyjubjub/lib/Field');
// const BN = require('bn.js');
const crypto = require('crypto');

// Baby Jubjub curve order [251 bit value]
const BABY_JUBJUB_ORDER = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');
// Ed25519 curve order  [>252 bit value]
const ED25519_ORDER = BigInt('7237005577332262213973186563042994240857116359379907606001950938285454250989');
// BN254 curve order  [254 bit value]
const BN254_ORDER = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

//ed25519 generator constants:
// X:
// 15112221349535400772501151409588531511454012693041857206046113283949847762202 [decimal]
// 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A
// Y:
// 46316835694926478169428394003475163141307993866256225615783033603165251855960 [decimal]
// 0x6666666666666666666666666666666666666666666666666666666666666658
// Compressed HEX:
// 0x5866666666666666666666666666666666666666666666666666666666666666

// Ed25519 field modulus q = 2^255 - 19
const Q = BigInt('57896044618658097711785492504343953926634992332820282019728792003956564819949');
// Ed25519 curve parameter d = -121665 / 121666 mod q
const D = BigInt('37095705934669439343138083508754565189542113879843219016388785533085940283555');

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

function bigIntTo32ByteArray_le(bigInt) {
  // Ensure BigInt is non-negative and fits in 32 bytes
  if (bigInt < 0n) throw new Error('BigInt must be non-negative');
  if (bigInt >= 2n ** 256n) throw new Error('BigInt too large for 32 bytes');

    // Create a 32-byte buffer (256 bits)
    const byteArray = new Uint8Array(32);
    
    // Write BigInt to array in little-endian order
    let value = bigInt;
    for (let i = 0; i < 32; i++) {
        byteArray[i] = Number(value & 0xffn); // Get least significant byte
        value >>= 8n; // Shift right by 8 bits
    }

    return byteArray;
}

function bigIntTo32ByteHex_le(bigInt) {
    // Ensure BigInt is non-negative and fits in 32 bytes
    if (bigInt < 0n) throw new Error('BigInt must be non-negative');
    if (bigInt >= 2n ** 256n) throw new Error('BigInt too large for 32 bytes');

    // Create a 32-byte buffer (256 bits)
    const buffer = Buffer.alloc(32);

    // Write BigInt to buffer in little-endian format
    let value = bigInt;
    for (let i = 0; i < 32; i++) {
        buffer[i] = Number(value & 0xffn); // Get least significant byte
        value >>= 8n; // Shift right by 8 bits
    }

    // Convert value to hex string
    return buffer.toString('hex').padStart(64, '0');
}

function littleEndianHexToBigInt(hexString) {
    // Validate hex string
    if (!/^[0-9a-fA-F]{64}$/.test(hexString)) {
        throw new Error('Hex string must be 64 characters (32 bytes):', hexString);
    }

    // Convert hex string to byte array
    const byteArray = Buffer.from(hexString, 'hex');

    // Convert little-endian byte array to BigInt
    let result = 0n;
    for (let i = 31; i >= 0; i--) {
        result = (result << 8n) | BigInt(byteArray[i]);
    }

    return result;
}


// // Function to compute SHA-256 hash of concatenated hex strings
// function hashPoints(...points) {
//     const concatenated = points.map(p => p.toString('hex')).join('');
//     return new BN(crypto.createHash('sha256').update(concatenated).digest('hex'), 16);
// }

// // Function to validate if (x, y) is a point on the Ed25519 curve
// function isPointOnCurve_ed25519(x, y) {
//     const x2 = (x * x) % Q;
//     const y2 = (y * y) % Q;
//     const left = (y2 - x2 + Q) % Q; // y^2 - x^2
//     const right = (1n + (D * x2 * y2) % Q) % Q; // 1 + d * x^2 * y^2
//     return left === right;
// }

// function fromHex_babyjubjub(pHex) {
//     const p_bigint = littleEndianHexToBigInt(pHex);
//     const fq = new FQ(p_bigint);
//     const p = Point.fromY(fq);

//     console.log('p:', p);

//     // Ensure the number is an integer
//     // if (!p.x.n.isInteger()) {
//     //     throw new Error('BigNumber must be an integer to convert to BigInt');
//     // }
//     console.log('p.x:', p.x);

//     const x = BigInt(p.x.toString())
//     console.log('x:', x);
//     if (!p.y.n.isInteger()) {
//         throw new Error('BigNumber must be an integer to convert to BigInt');
//     }
//     const y = BigInt(p.y.n.toString())
//     console.log('y:', y);

//     throw new Error('STOP');

//     return CARP;
// }


function generateDLEQProof_simple(secret, blinding) {
    if (secret <= 0n) throw new Error('secret must be positive');
    if (secret >= BABY_JUBJUB_ORDER) throw new Error('secret too large for Baby Jubjub');
    if (blinding <= 0n) throw new Error('blinding must be positive');
    if (blinding >= BABY_JUBJUB_ORDER) throw new Error('blinding too large for Baby Jubjub');

    //Baby Jubjub constants

    // Compute T = secret * G1 (Baby Jubjub)
    const T = mulPointEscalar(Base8, secret);
    console.log('T:', T);

    //Ed25519 constants
    const g2 = ed25519.ExtendedPoint.BASE;

    // Compute S = secret * G2 (Ed25519)
    const S = g2.multiply(secret); // secret * G2
    console.log('S:', S);

    // Compute commitments: R1 = blinding * G1 (Baby Jubjub)
    const R1 = mulPointEscalar(Base8, blinding);
    console.log('R1:', R1);

    // Compute commitments: R2 = blinding * G2 (Ed25519)
    const R2 = g2.multiply(blinding);
    console.log('R2:', R2);

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

    // Compute response s = blinding - c * secret
    const s = blinding - (challenge_bigint * secret);
    console.log('s:', s);
    if (s >= 0n) throw new Error('s must be negative');

    const s_div_BabyJubJub = (s / BABY_JUBJUB_ORDER) - 1n;
    if ((s_div_BabyJubJub * BigInt('-1')) >= BN254_ORDER) throw new Error('s div BABY_JUBJUB_ORDER too large for BN254');
    console.log('s_div_BabyJubJub:', s_div_BabyJubJub);

    const s_div_ed25519 = (s / ED25519_ORDER) - 1n;
    if ((s_div_ed25519 * BigInt('-1')) >= BN254_ORDER) throw new Error('s div ED25519_ORDER too large for BN254');
    console.log('s_div_ed25519:', s_div_ed25519);

    // Compute response s = blinding - c * secret mod BABY_JUBJUB_ORDER
    const challenge_BabyJubJub = challenge_bigint % BABY_JUBJUB_ORDER;
    var s_BabyJubJub = (blinding - ((challenge_BabyJubJub * secret) % BABY_JUBJUB_ORDER)) % BABY_JUBJUB_ORDER;
    if (s_BabyJubJub < 0) {
        s_BabyJubJub = s_BabyJubJub + BABY_JUBJUB_ORDER;
    }
    if (s_BabyJubJub <= 0n) throw new Error('s on Baby Jubjub must be non-negative');
    if (s_BabyJubJub >= BABY_JUBJUB_ORDER) throw new Error('s too large for Baby Jubjub');
    console.log('s_BabyJubJub:', s_BabyJubJub);

    // Compute response s = blinding - c * secret mod ED25519_ORDER
    const challenge_ed25519 = challenge_bigint % ED25519_ORDER;
    var s_ed25519 = (blinding - ((challenge_ed25519 * secret) % ED25519_ORDER)) % ED25519_ORDER;
    if (s_ed25519 < 0) {
        s_ed25519 = s_ed25519 + ED25519_ORDER;
    }
    if (s_ed25519 <= 0n) throw new Error('s on Ed25519 must be non-negative');
    if (s_ed25519 >= ED25519_ORDER) throw new Error('s too large for Ed25519');
    console.log('s_ed25519:', s_ed25519);
    console.log('s_ed25519 % BABY_JUBJUB_ORDER:', s_ed25519 % BABY_JUBJUB_ORDER);

    //Confirm!
    const s1_g1 = mulPointEscalar(Base8, s_BabyJubJub);
    const c_T = mulPointEscalar(T, challenge_BabyJubJub);
    const R1_calc = addPoint(s1_g1, c_T);
    if (R1_calc[0] != R1[0]) throw new Error('R1_calc != R1');
    if (R1_calc[1] != R1[1]) throw new Error('R1_calc != R1');

    const s2_g2 = g2.multiply(s_ed25519);
    const c_S = S.multiply(challenge_ed25519);
    const R2_calc = s2_g2.add(c_S);
    console.log('R2_calc:', R2_calc);
    console.log('R2:', R2);
    if (R2_calc.equals(R2) == false) throw new Error('R2_calc != R2');

    //

    return {
        public: {
            T: packPoint(T).toString(16),
            S: S.toHex(),
        },
        proof: {
            c: challenge_hash,
            s1: s_BabyJubJub.toString(16, 64),
            s2: s_ed25519.toString(16, 64),
        },
        commitments: {
            R1: packPoint(R1).toString(16),
            R2: R2.toHex(),
        },
        extra: {
            secret: secret.toString(16, 64),
            blinding: blinding.toString(16, 64),
            s_negative: (s * BigInt('-1')).toString(16, 64),
            s1_div: (s_div_BabyJubJub * BigInt('-1')).toString(16, 64),
            s2_div: (s_div_ed25519 * BigInt('-1')).toString(16, 64),
        }
    };
}

// function verifyDLEQProof_simple(c, s1, s2, a1Hex, b1Hex, a2Hex, b2Hex, THex, q1Hex, SHex, q2Hex, h1_scalar, g2Hex, h2Hex) {
function verifyDLEQProof_simple(c, s1, s2, R1Hex, R2Hex, THex, SHex) {
    if (c <= 0n) throw new Error('c must be non-negative');
    // if (c >= BABY_JUBJUB_ORDER) throw new Error('c too large for Baby Jubjub');
    if (s1 <= 0n) throw new Error('s1 must be non-negative');
    if (s1 >= BABY_JUBJUB_ORDER) throw new Error('s1 too large for Baby Jubjub');
    if (s2 <= 0n) throw new Error('s2 must be non-negative');
    if (s2 >= ED25519_ORDER) throw new Error('s2 too large for Ed25519');

    // const h1 = mulPointEscalar(Base8, h1_scalar);

    const T = unpackPoint(BigInt('0x' + THex));
    // // var q1 = unpackPoint(BigInt('0x' + q1Hex));
    // var a1 = unpackPoint(BigInt('0x' + a1Hex));
    // if (a1 == null) throw new Error('a1 is null');
    // var b1 = unpackPoint(BigInt('0x' + b1Hex));
    // if (b1 == null) throw new Error('b1 is null');

    // var g2 = ed25519.ExtendedPoint.fromHex(g2Hex);
    // var h2 = ed25519.ExtendedPoint.fromHex(h2Hex);
    const S = ed25519.ExtendedPoint.fromHex(SHex);
    // var q2 = ed25519.ExtendedPoint.fromHex(q2Hex);
    // var a2 = ed25519.ExtendedPoint.fromHex(a2Hex);
    // var b2 = ed25519.ExtendedPoint.fromHex(b2Hex);

    // //Baby Jubjub
    // const s_g1 = mulPointEscalar(Base8, s);
    // console.log('s_g1:', s_g1);
    // const c_T = mulPointEscalar(T, c);
    // console.log('c_T:', c_T);
    // const a1_calc = addPoint(s_g1, c_T);
    // console.log('a1_calc:', a1_calc);
    // if (a1_calc[0] != a1[0]) throw new Error('a1_calc != a1');
    // if (a1_calc[1] != a1[1]) throw new Error('a1_calc != a1');

    // const s_h1 = mulPointEscalar(h1, s);
    // console.log('s_h1:', s_h1);
    // const c_q1 = mulPointEscalar(q1, c);
    // console.log('c_q1:', c_q1);
    // const b1_calc = addPoint(s_h1, c_q1);
    // console.log('b1_calc:', b1_calc);
    // if (b1_calc[0] != b1[0]) throw new Error('b1_calc != b1');
    // if (b1_calc[1] != b1[1]) throw new Error('b1_calc != b1');

    // //Ed25519
    // const s_g2 = g2.multiply(s);
    // console.log('s_g2:', s_g2);
    // const c_S = S.multiply(c);
    // console.log('c_S:', c_S);
    // const a2_calc = s_g2.add(c_S);
    // console.log('a2_calc:', a2_calc);
    // console.log('a2_calc:', a2_calc.toHex());
    // console.log('a2:', a2);
    // if (a2_calc.equals(a2) == false) throw new Error('a2_calc != a2');

    // const s_h2 = h2.multiply(s);
    // console.log('s_h2:', s_h2);
    // const c_q2 = q2.multiply(c);
    // console.log('c_q2:', c_q2);
    // const b2_calc = s_h2.add(c_q2);
    // console.log('b2_calc:', b2_calc);
    // if (b2_calc.equals(b2) == false) throw new Error('b2_calc != b2');

    //Ed25519 constants
    const g2 = ed25519.ExtendedPoint.BASE;

    const R1 = unpackPoint(BigInt('0x' + R1Hex));

    const R2 = ed25519.ExtendedPoint.fromHex(R2Hex);

    const challenge_BabyJubJub = c % BABY_JUBJUB_ORDER;
    const s_g1 = mulPointEscalar(Base8, s1);
    const c_T = mulPointEscalar(T, challenge_BabyJubJub);
    const R1_calc = addPoint(s_g1, c_T);
    if (R1_calc[0] != R1[0]) throw new Error('R1_calc != R1');
    if (R1_calc[1] != R1[1]) throw new Error('R1_calc != R1');

    const challenge_ed25519 = c % ED25519_ORDER;
    const s_g2 = g2.multiply(s2);
    const c_S = S.multiply(challenge_ed25519);
    const R2_calc = s_g2.add(c_S);
    console.log('R2_calc:', R2_calc);
    console.log('R2:', R2);
    if (R2_calc.equals(R2) == false) throw new Error('R2_calc != R2');

    //Verified
    console.log('Verified!');
}


// function generateDLEQProof_complex(secret, blinding, h1Hex, h2Hex) {
//     if (secret <= 0n) throw new Error('secret must be positive');
//     if (secret >= BABY_JUBJUB_ORDER) throw new Error('secret too large for Baby Jubjub');
//     if (blinding <= 0n) throw new Error('blinding must be positive');
//     if (blinding >= BABY_JUBJUB_ORDER) throw new Error('blinding too large for Baby Jubjub');

//     //Baby Jubjub constants
//     var g1 = Base8;
//     var h1 = unpackPoint(BigInt('0x' + h1Hex));

//     //Ed25519 constants
//     var g2 = ed25519.ExtendedPoint.BASE;
//     var h2 = ed25519.ExtendedPoint.fromHex(h2Hex);

//     // Compute T = secret * G1 (Baby Jubjub)
//     const T = mulPointEscalar(g1, secret);
//     console.log('T:', T);

//     // Compute S = secret * G2 (Ed25519)
//     const S = g2.multiply(secret);
//     console.log('S:', S);

//     // Compute Q1 = x * H1 for Baby Jubjub
//     const q1 = mulPointEscalar(h1, secret);

//     // Compute Q2 = x * H2 for Ed25519
//     const q2 = h2.multiply(secret);

//     // Compute commitments: A1 = blinding * G1, B1 = blinding * H1 (Baby Jubjub)
//     const a1 = mulPointEscalar(g1, blinding);
//     const b1 = mulPointEscalar(h1, blinding);

//     // Compute commitments: A2 = blinding * G2, B2 = blinding * H2 (Ed25519)
//     const a2 = g2.multiply(blinding);
//     const b2 = h2.multiply(blinding);

//     // Compute challenge c = H(NIZK_DLEQ HASH_HEADER_CONSTANT, T, Q1, S, Q2, A1, B1, A2, B2)
//     const challenge_preimage = Buffer.from([
//         ...Array(32).fill(0x00), // NIZK_DLEQ HASH_HEADER_CONSTANT
//         ...bigIntTo32ByteArray(packPoint(T)),
//         ...bigIntTo32ByteArray(packPoint(q1)),
//         ...S.toRawBytes(),
//         ...q2.toRawBytes(),
//         ...bigIntTo32ByteArray(packPoint(a1)),
//         ...bigIntTo32ByteArray(packPoint(b1)),
//         ...A2.toRawBytes(),
//         ...B2.toRawBytes(),
//     ]);
//     const challenge_hash = blake.blake2sHex(challenge_preimage);
//     const challenge_bigint = BigInt('0x' + challenge_hash); // Convert hex to BigInt

//     // Compute response s = blinding - c * secret mod BABY_JUBJUB_ORDER
//     const challenge_BabyJubJub = challenge_bigint % BABY_JUBJUB_ORDER;
//     var s_BabyJubJub = (blinding - ((challenge_BabyJubJub * secret) % BABY_JUBJUB_ORDER)) % BABY_JUBJUB_ORDER;
//     if (s_BabyJubJub < 0) {
//         s_BabyJubJub = s_BabyJubJub + BABY_JUBJUB_ORDER;
//     }
//     if (s_BabyJubJub <= 0n) throw new Error('s must be non-negative');
//     if (s_BabyJubJub >= BABY_JUBJUB_ORDER) throw new Error('s too large for Baby Jubjub');
//     console.log('s_BabyJubJub:', s_BabyJubJub);

//     // Compute response s = blinding - c * secret mod ED25519_ORDER
//     const challenge_ed25519 = challenge_bigint % ED25519_ORDER;
//     var s_ed25519 = (blinding - ((challenge_ed25519 * secret) % ED25519_ORDER)) % ED25519_ORDER;
//     if (s_ed25519 < 0) {
//         s_ed25519 = s_ed25519 + ED25519_ORDER;
//     }
//     if (s_ed25519 <= 0n) throw new Error('s must be non-negative');
//     if (s_ed25519 >= ED25519_ORDER) throw new Error('s too large for Ed25519');
//     console.log('s_ed25519:', s_ed25519);
//     console.log('s_ed25519 % BABY_JUBJUB_ORDER:', s_ed25519 % BABY_JUBJUB_ORDER);

//     //Confirm!
//     const s1_g1 = mulPointEscalar(g1, s_BabyJubJub);
//     const c_T = mulPointEscalar(T, challenge_BabyJubJub);
//     const R1_calc = addPoint(s1_g1, c_T);
//     if (R1_calc[0] != R1[0]) throw new Error('R1_calc != R1');
//     if (R1_calc[1] != R1[1]) throw new Error('R1_calc != R1');

//     const s2_g2 = g2.multiply(s_ed25519);
//     const c_S = S.multiply(challenge_ed25519);
//     const R2_calc = s2_g2.add(c_S);
//     console.log('R2_calc:', R2_calc);
//     console.log('R2:', R2);
//     if (R2_calc.equals(R2) == false) throw new Error('R2_calc != R2');

//     //

//     return {
//         public: {
//             T: packPoint(T).toString(16),
//             S: S.toHex(),
//         },
//         proof: {
//             c: challenge_hash,
//             s1: s_BabyJubJub.toString(16, 64),
//             s2: s_ed25519.toString(16, 64),
//         },
//         commitments: {
//             R1: packPoint(R1).toString(16),
//             R2: R2.toHex(),
//         }
//     };
// }

// // function verifyDLEQProof_complex(c, s1, s2, a1Hex, b1Hex, a2Hex, b2Hex, THex, q1Hex, SHex, q2Hex, h1_scalar, g2Hex, h2Hex) {
// function verifyDLEQProof_complex(c, s1, s2, R1Hex, R2Hex, THex, SHex) {
//     if (c <= 0n) throw new Error('c must be non-negative');
//     // if (c >= BABY_JUBJUB_ORDER) throw new Error('c too large for Baby Jubjub');
//     if (s1 <= 0n) throw new Error('s1 must be non-negative');
//     if (s1 >= BABY_JUBJUB_ORDER) throw new Error('s1 too large for Baby Jubjub');
//     if (s2 <= 0n) throw new Error('s2 must be non-negative');
//     if (s2 >= ED25519_ORDER) throw new Error('s2 too large for Ed25519');

//     // const h1 = mulPointEscalar(Base8, h1_scalar);

//     var T = unpackPoint(BigInt('0x' + THex));
//     // // var q1 = unpackPoint(BigInt('0x' + q1Hex));
//     // var a1 = unpackPoint(BigInt('0x' + a1Hex));
//     // if (a1 == null) throw new Error('a1 is null');
//     // var b1 = unpackPoint(BigInt('0x' + b1Hex));
//     // if (b1 == null) throw new Error('b1 is null');

//     // var g2 = ed25519.ExtendedPoint.fromHex(g2Hex);
//     // var h2 = ed25519.ExtendedPoint.fromHex(h2Hex);
//     var S = ed25519.ExtendedPoint.fromHex(SHex);
//     // var q2 = ed25519.ExtendedPoint.fromHex(q2Hex);
//     // var a2 = ed25519.ExtendedPoint.fromHex(a2Hex);
//     // var b2 = ed25519.ExtendedPoint.fromHex(b2Hex);

//     // //Baby Jubjub
//     // const s_g1 = mulPointEscalar(Base8, s);
//     // console.log('s_g1:', s_g1);
//     // const c_T = mulPointEscalar(T, c);
//     // console.log('c_T:', c_T);
//     // const a1_calc = addPoint(s_g1, c_T);
//     // console.log('a1_calc:', a1_calc);
//     // if (a1_calc[0] != a1[0]) throw new Error('a1_calc != a1');
//     // if (a1_calc[1] != a1[1]) throw new Error('a1_calc != a1');

//     // const s_h1 = mulPointEscalar(h1, s);
//     // console.log('s_h1:', s_h1);
//     // const c_q1 = mulPointEscalar(q1, c);
//     // console.log('c_q1:', c_q1);
//     // const b1_calc = addPoint(s_h1, c_q1);
//     // console.log('b1_calc:', b1_calc);
//     // if (b1_calc[0] != b1[0]) throw new Error('b1_calc != b1');
//     // if (b1_calc[1] != b1[1]) throw new Error('b1_calc != b1');

//     // //Ed25519
//     // const s_g2 = g2.multiply(s);
//     // console.log('s_g2:', s_g2);
//     // const c_S = S.multiply(c);
//     // console.log('c_S:', c_S);
//     // const a2_calc = s_g2.add(c_S);
//     // console.log('a2_calc:', a2_calc);
//     // console.log('a2_calc:', a2_calc.toHex());
//     // console.log('a2:', a2);
//     // if (a2_calc.equals(a2) == false) throw new Error('a2_calc != a2');

//     // const s_h2 = h2.multiply(s);
//     // console.log('s_h2:', s_h2);
//     // const c_q2 = q2.multiply(c);
//     // console.log('c_q2:', c_q2);
//     // const b2_calc = s_h2.add(c_q2);
//     // console.log('b2_calc:', b2_calc);
//     // if (b2_calc.equals(b2) == false) throw new Error('b2_calc != b2');

//     //Ed25519 constants
//     var g2 = ed25519.ExtendedPoint.BASE;

//     var R1 = unpackPoint(BigInt('0x' + R1Hex));

//     var R2 = ed25519.ExtendedPoint.fromHex(R2Hex);

//     const challenge_BabyJubJub = c % BABY_JUBJUB_ORDER;
//     const s_g1 = mulPointEscalar(Base8, s1);
//     const c_T = mulPointEscalar(T, challenge_BabyJubJub);
//     const R1_calc = addPoint(s_g1, c_T);
//     if (R1_calc[0] != R1[0]) throw new Error('R1_calc != R1');
//     if (R1_calc[1] != R1[1]) throw new Error('R1_calc != R1');

//     const challenge_ed25519 = c % ED25519_ORDER;
//     const s_g2 = g2.multiply(s2);
//     const c_S = S.multiply(challenge_ed25519);
//     const R2_calc = s_g2.add(c_S);
//     console.log('R2_calc:', R2_calc);
//     console.log('R2:', R2);
//     if (R2_calc.equals(R2) == false) throw new Error('R2_calc != R2');

//     //Verified
//     console.log('Verified!');
// }


//Init: VerifyWitness0 + VerifyWitnessSharing
console.log('Init: circuits/init/Prover.toml');
console.log('');

const secret = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;//BigInt('1') % BABY_JUBJUB_ORDER;
console.log('secret:', secret);
// // Generate random scalar w
// const w = new BN(crypto.randomBytes(32)).umod(BABY_JUBJUB_ORDER);
const blinding = BigInt('0x' + crypto.randomBytes(32).toString("hex")) % BABY_JUBJUB_ORDER;//BigInt('1') % BABY_JUBJUB_ORDER;
console.log('blinding:', blinding);
// const h1_scalar = BigInt('1');
// const g2Hex = '5866666666666666666666666666666666666666666666666666666666666666';
// const h2Hex = '5866666666666666666666666666666666666666666666666666666666666666';

//Prove
const proof = generateDLEQProof_simple(secret, blinding);
console.log('proof:', proof);

//Verify
verifyDLEQProof_simple(
    BigInt('0x' + proof.proof.c), BigInt('0x' + proof.proof.s1), BigInt('0x' + proof.proof.s2),
    proof.commitments.R1, proof.commitments.R2,
    proof.public.T, proof.public.S);
