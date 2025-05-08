var blake = require('blakejs')
const { packPoint, unpackPoint, Base8, mulPointEscalar, Point, addPoint } =require( "@zk-kit/baby-jubjub")

//Constants
const nonce_peer = BigInt('1');
const blinding = BigInt('1');
const a_1 = BigInt('2');
const r_1 = BigInt('1');
const r_2 = BigInt('1');
const privateKey_peer = BigInt('1');
const privateKey_KES = BigInt('1');

//Derives
const pubkey_peer = mulPointEscalar(Base8, privateKey_peer);
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
// Baby Jubjub curve order [251 bit value]
const L = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');


//Init/VerifyWitness0 + VerifyWitnessSharing
console.log('Init: circuits/init/Prover.toml');
console.log('');

var byteArray_VerifyWitness0 = Buffer.from([
  // ...Array(32).fill(0x00), // VerifyWitness0 HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(nonce_peer),
  ...bigIntTo32ByteArray(blinding),
]);
var hash_VerifyWitness0 = blake.blake2sHex(byteArray_VerifyWitness0);
var hashBig_VerifyWitness0 = BigInt('0x' + hash_VerifyWitness0); // Convert hex to BigInt

let witness_0 = hashBig_VerifyWitness0 % L;
let T_0 = mulPointEscalar(Base8, witness_0);

//FeldmanSecretShare_2_of_2

var c_0 = mulPointEscalar(Base8, witness_0);
var c_1 = mulPointEscalar(Base8, a_1);
var share_1 = (witness_0 + a_1) % L;
var share_2 = (share_1 + a_1) % L;

//Encrypt to peer
var ephemeral_1 = mulPointEscalar(Base8, r_1);
var shared_secret_1 = mulPointEscalar(pubkey_peer, r_1);
var message_point_1 = mulPointEscalar(Base8, share_1);
var cipher_1 = addPoint(message_point_1, shared_secret_1);
var fi_1 = ephemeral_1;
var enc_1 = cipher_1;

//Encrypt to KES
var ephemeral_2 = mulPointEscalar(Base8, r_2);
var shared_secret_2 = mulPointEscalar(pubkey_peer, r_2);
var message_point_2 = mulPointEscalar(Base8, share_2);
var cipher_2 = addPoint(message_point_2, shared_secret_2);
var fi_2 = ephemeral_2;
var enc_2 = cipher_2;

console.log(`a_1 = "${a_1.toString()}"`);
console.log(`blinding = "${blinding.toString()}"`);
console.log(`nonce_peer = "${nonce_peer.toString()}"`);
console.log(`r_1 = "${r_1.toString()}"`);
console.log(`r_2 = "${r_2.toString()}"`);
console.log(`share_1 = "${share_1.toString()}"`);
console.log(`share_2 = "${share_2.toString()}"`);
console.log(`witness_0 = "${witness_0.toString()}"`);

console.log('');
console.log('[T_0]');
console.log(`  x="0x${T_0[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${T_0[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[c_0]');
console.log(`  x="0x${c_0[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${c_0[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[c_1]');
console.log(`  x="0x${c_1[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${c_1[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[enc_1]');
console.log(`  x="0x${enc_1[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${enc_1[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[enc_2]');
console.log(`  x="0x${enc_2[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${enc_2[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[fi_1]');
console.log(`  x="0x${fi_1[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${fi_1[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[fi_2]');
console.log(`  x="0x${fi_2[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${fi_2[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[pubkey_KES]');
console.log(`  x="0x${pubkey_KES[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${pubkey_KES[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[pubkey_peer]');
console.log(`  x="0x${pubkey_peer[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${pubkey_peer[1].toString(16).padStart(64, '0')}"`);

//Update/VerifyCOF
console.log('');
console.log('Update: circuits/update/Prover.toml');
console.log('');

const byteArray = Buffer.from([
  ...Array(32).fill(0x00), // VCOF HASH_HEADER_CONSTANT
  ...bigIntTo32ByteArray(witness_0),
]);
const hash = blake.blake2sHex(byteArray);
const hashBig = BigInt('0x' + hash); // Convert hex to BigInt

var witness_i = hashBig % L;
console.log(`witness_i = "${witness_i.toString()}"`);
console.log(`witness_im1 = "${witness_0.toString()}"`);

let T_i = mulPointEscalar(Base8, witness_i);

console.log('');
console.log('[T_i]');
console.log(`  x="0x${T_i[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${T_i[1].toString(16).padStart(64, '0')}"`);

console.log('');
console.log('[T_im1]');
console.log(`  x="0x${T_0[0].toString(16).padStart(64, '0')}"`);
console.log(`  y="0x${T_0[1].toString(16).padStart(64, '0')}"`);
