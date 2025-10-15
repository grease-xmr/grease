import {Base8, mulPointEscalar, addPoint, r, inCurve} from "@zk-kit/baby-jubjub"
import {randomBytes} from "crypto";

function randomBigInt() {
    const buf = randomBytes(25);
    return BigInt('0x' + buf.toString('hex'));
}

function createCase() {
    let k = r;
    while (k >= r) {
        k = randomBigInt();
    }
    const base = mulPointEscalar(Base8, k);
    console.assert(inCurve(base), "Base point is not in curve");
    const point2 = mulPointEscalar(base, k);
    console.assert(inCurve(point2), "k.G is not in curve");
    const point3 = addPoint(base, point2);
    console.assert(inCurve(point3), "k.G + G is not in curve");
    return [k.toString(10), strPoint(base), strPoint(point2), strPoint(point3)];
}

function strPoint(p) {
    return [p[0].toString(10), p[1].toString(10)];
}

function generateCases(numCases = 250) {
    const cases = [];
    for (let i = 0; i < numCases; i++) {
        cases.push(createCase());
    }
    return cases;
}

let cases = generateCases(500);
// Output the cases as a JSON array of 4-tuples:
// k = scalar
// P = k.g
// P2 = k.P
// P3 = P + P2
// [k, P, P1, P2]
// Save test cases with `node create_vectors.mjs > test_vectors.json
console.log(JSON.stringify(cases, null, 2));

