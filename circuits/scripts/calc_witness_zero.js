var blake = require('blakejs')


const nonce_peer = BigInt(1);
const blinding = BigInt(1);


//VerifyWitness0

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
  // ...Array(32).fill(0x00), // VerifyWitness0 HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(nonce_peer),
  ...bigIntTo32ByteArray(blinding),
]);
// console.log('byteArray length:', byteArray.length);
// console.log('byteArray:', byteArray);
const hash = blake.blake2sHex(byteArray);
// console.log('BLAKE2s Hash hex:', hash);
const hashBig = BigInt('0x' + hash); // Convert hex to BigInt
// console.log('BLAKE2s Hash decimal:', hashBig.toString()); // Print decimal value

// Baby Jubjub curve order [251 bit value]
const L = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');

var witness_0 = hashBig % L;
console.log('witness_0:', witness_0.toString()); // Print decimal value
