// const { secp256k1, ed25519 } = require('@noble/curves');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { ed25519 } = require('@noble/curves/ed25519');
const { sha256 } = require('@noble/hashes/sha256');
const { program } = require('commander');

// Function to generate a DLEQ proof across two curves
function generateDLEQProof(a, G2, G1) {
    // Validate inputs
    const n1 = BigInt(secp256k1.CURVE.n.toString()); // Order of secp256k1
    const n2 = BigInt(ed25519.CURVE.n.toString()); // Order of Curve25519
    if (n1 < n2) {
        throw new Error('n2 != min(n1, n2))');
    }
    if (a <= 0n || a >= n1 || a >= n2) {
        throw new Error('Scalar a must be in [1, min(n1, n2))');
    }

    // Compute A = a * G1 (secp256k1) and C = a * G2 (Curve25519)
    const A = G1.multiply(a);
    const C = G2.multiply(a);

    // Generate proof
    const k = BigInt('1');//BigInt('0x' + Buffer.from(sha256(Math.random().toString())).toString('hex')) % n2; // Random scalar
    const kG = G1.multiply(k); // k * G1
    const kB = G2.multiply(k); // k * B

    // Compute challenge c = H(kG || kB || A || B || C)
    const cHash = sha256(Buffer.concat([
        Buffer.from(kG.toHex(), 'hex'),
        Buffer.from(kB.toHex(), 'hex'),
        Buffer.from(A.toHex(), 'hex'),
        Buffer.from(G2.toHex(), 'hex'),
        Buffer.from(C.toHex(), 'hex')
    ]));
    const c = BigInt('0x' + Buffer.from(cHash).toString('hex')) % n2;

    // Compute response r = k - c * a mod n2
    var r = (k - c * a) % n2;
    if (r < 0n) r += n2;
    console.log('r:', r);
    console.log('n2:', n2);

    return { proof: { c, r }, A, C };
}

// Function to verify a DLEQ proof
function verifyDLEQProof(A, G2, C, proof, G1) {
    const n1 = BigInt(secp256k1.CURVE.n.toString());
    const n2 = BigInt(ed25519.CURVE.n.toString());
    const { c, r } = proof;

    // Validate inputs
    if (r >= n2 || c >= n2) {
        throw new Error('Proof scalars out of range');
    }

    // Compute R1 = r * G1 + c * A (secp256k1)
    const rG = G1.multiply(r);
    const cA = A.multiply(c);
    const R1 = rG.add(cA);

    // Compute R2 = r * G2 + c * C (Curve25519)
    const rB = G2.multiply(r);
    const cC = C.multiply(c);
    const R2 = rB.add(cC);

    // Compute challenge c' = H(R1 || R2 || A || B || C)
    const cPrimeHash = sha256(Buffer.concat([
        Buffer.from(R1.toHex(), 'hex'),
        Buffer.from(R2.toHex(), 'hex'),
        Buffer.from(A.toHex(), 'hex'),
        Buffer.from(G2.toHex(), 'hex'),
        Buffer.from(C.toHex(), 'hex')
    ]));
    const cPrime = BigInt('0x' + Buffer.from(cPrimeHash).toString('hex')) % n2;
    console.log('c:', c);
    console.log('cPrime:', cPrime);

    // Verify c == c'
    return c === cPrime;
}

// // Command line interface
// program
//     .version('1.0.0')
//     .description('Run DLEQ protocol across secp256k1 and Curve25519')
//     .requiredOption('-a, --scalar <decimal>', 'Secret scalar a')
//     .requiredOption('-b, --point-b <hex>', 'Point B on Curve25519 (hex)')
//     .action((options) => {
        // try {
            const a = BigInt("12345678901234567890");
            const G2 = ed25519.ExtendedPoint.fromHex("5866666666666666666666666666666666666666666666666666666666666666");
            console.log('B (Curve25519):', G2);
            const G1 = secp256k1.ProjectivePoint.BASE;

            // Generate proof
            const { proof, A, C } = generateDLEQProof(a, G2, G1);
            console.log('Proof:', { c: proof.c.toString(), r: proof.r.toString() });
            console.log('A (secp256k1):', A);
            console.log('C (Curve25519):', C);

            // Verify proof
            const isValid = verifyDLEQProof(
                A,
                G2,
                C,
                proof,
                G1
            );
            console.log('Proof valid:', isValid);
        // } catch (error) {
        //     console.error('Error:', error.message);
        //     process.exit(1);
        // }
//     });

// program.parse(process.argv);