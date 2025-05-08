const { packPoint, unpackPoint, Base8, mulPointEscalar, Point, addPoint } =require( "@zk-kit/baby-jubjub")


// Constant private key (hex string, 32 bytes, in [1, l-1])
const privateKey = BigInt('2620261836311203598213044375580616887113191744718301538057144527281453186668');


let pubKey = mulPointEscalar(Base8, privateKey);

// Convert coordinates to hex strings (0x-prefixed)
const xHex = pubKey[0].toString(16).padStart(64, '0');
const yHex = pubKey[1].toString(16).padStart(64, '0');

// Output public key
console.log('Baby Jubjub Public Key:');
console.log(`  x: 0x${xHex}`);
console.log(`  y: 0x${yHex}`);
