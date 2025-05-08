const blake = require('blakejs')
const { Base8, mulPointEscalar } =require( "@zk-kit/baby-jubjub")


const witness_im1 = BigInt('1812819055671836081919082473246651311844184517312342866801190068457152448493');

//VerifyCOF

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

const byteArray = Buffer.from([
  ...Array(32).fill(0x00), // VCOF HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(witness_im1),
]);
const hash = blake.blake2sHex(byteArray);
const hashBig = BigInt('0x' + hash); // Convert hex to BigInt

// Baby Jubjub curve order [251 bit value]
const L = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');

const witness_i = hashBig % L;
console.log('witness_i decimal:', witness_i.toString()); // Print decimal value

let T_i = mulPointEscalar(Base8, witness_i);

// Output T_i
console.log('T_i Public Key:');
console.log(`  x: 0x${T_i[0].toString(16).padStart(64, '0')}`);
console.log(`  y: 0x${T_i[1].toString(16).padStart(64, '0')}`);
