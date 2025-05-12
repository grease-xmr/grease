const { Base8, mulPointEscalar, addPoint, Fr } =require( "@zk-kit/baby-jubjub")


const message = BigInt('1812819055671836081919082473246651311844184517312342866801190068457152448495');
const r = BigInt('1');
const pubkey_x = BigInt('0x0bb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051');
const pubkey_y = BigInt('0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b');


//encrypt_message

const ephemeral = mulPointEscalar(Base8, r);
// Output ephemeral
console.log('ephemeral:');
console.log(`  x: 0x${ephemeral[0].toString(16).padStart(64, '0')}`);
console.log(`  y: 0x${ephemeral[1].toString(16).padStart(64, '0')}`);

const pubkey = [
    Fr.e(pubkey_x),
    Fr.e(pubkey_y)
];

const shared_secret = mulPointEscalar(pubkey, r);

const message_point = mulPointEscalar(Base8, message);

const cipher = addPoint(message_point, shared_secret);
console.log('cipher:');
console.log(`  x: 0x${cipher[0].toString(16).padStart(64, '0')}`);
console.log(`  y: 0x${cipher[1].toString(16).padStart(64, '0')}`);
