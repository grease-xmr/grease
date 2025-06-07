import argparse
import hashlib
import os
from fastecdsa import curve, point
import pysodium
from binascii import hexlify, unhexlify

# secp256k1 curve parameters
SECP256K1 = curve.secp256k1
N1 = SECP256K1.q  # Order: 115792089237316195423570985008687907852837564279074904382605163141518161494337

# Ed25519 curve parameters
N2 = 7237005577332262213973186563042994240857116359379907606001950938285454250989  # Order

def hash_points(*points):
    """Compute SHA-256 hash of concatenated point encodings."""
    concatenated = b''.join(point if isinstance(point, bytes) else point.to_bytes(33, 'big') for point in points)
    return int.from_bytes(hashlib.sha256(concatenated).digest(), 'big') % N2

def generate_dleq_proof(a, B, G1):
    """Generate a DLEQ proof for A = a*G1 (secp256k1) and C = a*B (Ed25519)."""
    # Validate inputs
    if a <= 0 or a >= N1 or a >= N2:
        raise ValueError("Scalar a must be in [1, min(n1, n2))")
    if len(B) != 32:
        raise ValueError("Point B must be a 32-byte Ed25519 point")
    # if not pysodium.crypto_core_ed25519_is_valid_point(B):
    #     raise ValueError("Point B must be a valid Ed25519 point")

    # Compute A = a * G1 (secp256k1)
    A = a * G1
    A_bytes = A.to_bytes(33, 'big')  # Compressed point

    # Compute C = a * B (Ed25519)
    # pysodium expects little-endian scalar
    a_bytes = a.to_bytes(32, 'little')
    C = pysodium.crypto_scalarmult(a_bytes, B)

    # Generate proof
    k = int.from_bytes(os.urandom(32), 'big') % N2  # Random scalar
    kG = (k * G1).to_bytes(33, 'big')  # k * G1 (secp256k1)
    k_bytes = k.to_bytes(32, 'little')
    kB = pysodium.crypto_scalarmult(k_bytes, B)  # k * B (Ed25519)

    # Compute challenge c = H(kG || kB || A || B || C)
    c = hash_points(kG, kB, A_bytes, B, C)

    # Compute response r = k - c * a mod n2
    r = (k - c * a) % N2

    return {"c": c, "r": r}, A_bytes, C

def verify_dleq_proof(A, B, C, proof, G1):
    """Verify a DLEQ proof."""
    c, r = proof["c"], proof["r"]

    # Validate inputs
    if r >= N2 or c >= N2:
        raise ValueError("Proof scalars out of range")
    try:
        A_point = point.Point.from_bytes(A, SECP256K1)
    except ValueError:
        raise ValueError("Point A must be valid on secp256k1")
    if len(B) != 32 or len(C) != 32:
        raise ValueError("Points B and C must be 32-byte Ed25519 points")
    # if not pysodium.crypto_core_ed25519_is_valid_point(B) or not pysodium.crypto_core_ed25519_is_valid_point(C):
    #     raise ValueError("Points B and C must be valid Ed25519 points")

    # Compute R1 = r * G1 + c * A (secp256k1)
    A_point = point.Point.from_bytes(A, SECP256K1)
    R1 = r * G1 + c * A_point
    R1_bytes = R1.to_bytes(33, 'big')

    # Compute R2 = r * B + c * C (Ed25519)
    r_bytes = r.to_bytes(32, 'little')
    c_bytes = c.to_bytes(32, 'little')
    rB = pysodium.crypto_scalarmult(r_bytes, B)
    cC = pysodium.crypto_scalarmult(c_bytes, C)
    # Ed25519 point addition
    R2 = pysodium.crypto_core_ed25519_add(rB, cC)

    # Compute challenge c' = H(R1 || R2 || A || B || C)
    c_prime = hash_points(R1_bytes, R2, A, B, C)

    return c == c_prime

def main():
    parser = argparse.ArgumentParser(description="Run DLEQ protocol across secp256k1 and Ed25519")
    parser.add_argument("-a", "--scalar", type=int, required=True, help="Secret scalar a")
    parser.add_argument("-b", "--point-b", type=str, required=True, help="Point B on Ed25519 (hex)")
    args = parser.parse_args()

    try:
        a = args.scalar
        B = unhexlify(args.point_b)
        G1 = SECP256K1.G  # secp256k1 base point

        # Generate proof
        proof, A, C = generate_dleq_proof(a, B, G1)
        print("Proof:", {"c": str(proof["c"]), "r": str(proof["r"])})
        print("A (secp256k1, hex):", hexlify(A).decode())
        print("C (Ed25519, hex):", hexlify(C).decode())

        # Verify proof
        is_valid = verify_dleq_proof(A, B, C, proof, G1)
        print("Proof valid:", is_valid)
    except Exception as e:
        print("Error:", str(e))
        exit(1)

if __name__ == "__main__":
    main()