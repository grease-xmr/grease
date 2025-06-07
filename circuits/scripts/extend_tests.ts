import { Point, Base8, mulPointEscalar, addPoint, packPoint, r, inCurve } from "@zk-kit/baby-jubjub"

/**
 * Modular arithmetic: (a mod n)
 * @param {bigint} a - Input number
 * @param {bigint} n - Modulus
 * @returns {bigint} a mod n in [0, n)
 */
function mod(a: bigint, n: bigint): bigint {
    return ((a % n) + n) % n;
}


export function subtractPoint(P: Point<bigint>, Q: Point<bigint>): Point<bigint> {
    if (!inCurve(P) || !inCurve(Q)) {
        throw new Error('Points are not on the Baby Jubjub curve');
    }

    let x = mod(-Q[0], r);
    // let x = r - BigInt(Q.x);

    // Compute -Q = (-x_Q, y_Q)
    const negQ: Point<bigint> = [ x, Q[1] ];

    // Compute P + (-Q)
    return addPoint(P, negQ);}
