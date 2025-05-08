const { Base8, mulPointEscalar } =require( "@zk-kit/baby-jubjub")


const witness_0 = BigInt('1812819055671836081919082473246651311844184517312342866801190068457152448493');
const a_1 = BigInt('2');


//FeldmanSecretShare_2_of_2

const c_0 = mulPointEscalar(Base8, witness_0);
// Output c_0
console.log('c_0:');
console.log(`  x: 0x${c_0[0].toString(16).padStart(64, '0')}`);
console.log(`  y: 0x${c_0[1].toString(16).padStart(64, '0')}`);

const c_1 = mulPointEscalar(Base8, a_1);
// Output c_1
console.log('c_1:');
console.log(`  x: 0x${c_1[0].toString(16).padStart(64, '0')}`);
console.log(`  y: 0x${c_1[1].toString(16).padStart(64, '0')}`);

// Baby Jubjub curve order [251 bit value]
const L = BigInt('2736030358979909402780800718157159386076813972158567259200215660948447373041');

const share_1 = (witness_0 + a_1) % L;
console.log('share_1:', share_1.toString()); // Print decimal value

const share_2 = (share_1 + a_1) % L;
console.log('share_2:', share_2.toString()); // Print decimal value
