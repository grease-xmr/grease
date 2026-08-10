use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use blake2::Blake2b512;
use crate::Ed25519;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use dalek_ff_group::{EdwardsPoint, Scalar};
use digest::Digest;
use modular_frost::ThresholdKeys;
use musig::{musig, MusigError};
use zeroize::Zeroizing;

pub fn sort_pubkeys(keys: &mut [Curve25519PublicKey; 2]) {
    keys.sort_unstable_by(|a, b| a.to_compressed().as_bytes().cmp(b.to_compressed().as_bytes()));
}

fn musig_context(keys: &[Curve25519PublicKey; 2]) -> [u8; 64 + 5] {
    let mut result = [0u8; 64 + 5];
    result[..5].copy_from_slice(b"Musig");
    result[5..5 + 32].copy_from_slice(keys[0].to_compressed().as_bytes());
    result[5 + 32..5 + 64].copy_from_slice(keys[1].to_compressed().as_bytes());
    result
}

/// The MuSig context, compressed to the 32 bytes the `musig` crate accepts.
///
/// `musig` 0.6 takes a fixed `[u8; 32]` context where `modular-frost 0.8`'s `dkg::musig` took a
/// length-prefixed `&[u8]`. Grease's context is 69 bytes, so it is hashed down rather than truncated:
/// truncating at 32 would drop the whole of `P_B` and stop the context binding both keys.
fn compressed_musig_context(keys: &[Curve25519PublicKey; 2]) -> [u8; 32] {
    let hashed = Blake2b512::digest(musig_context(keys));
    let mut context = [0u8; 32];
    context.copy_from_slice(&hashed[..32]);
    context
}

pub fn musig_2_of_2(
    secret: &Curve25519Secret,
    sorted_pubkeys: &[Curve25519PublicKey; 2],
) -> Result<ThresholdKeys<Ed25519>, MusigError<Ed25519>> {
    let context = compressed_musig_context(sorted_pubkeys);
    let secret = Zeroizing::new(*secret.as_dalek_scalar());
    let pubkeys: [EdwardsPoint; 2] = [sorted_pubkeys[0].as_point(), sorted_pubkeys[1].as_point()];
    musig(context, secret, &pubkeys)
}

pub fn musig_dh_viewkey(secret: &Curve25519Secret, other: &Curve25519PublicKey) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let shared = *other.as_point() * secret.as_dalek_scalar();
    let hashed = Blake2b512::new().chain_update(b"MuSigViewKey").chain_update(shared.compress().as_bytes()).finalize();
    let mut bytes = [0u8; 64];
    bytes[..].copy_from_slice(hashed.as_slice());
    let private_view_key = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&bytes));
    let public_view_key = EdwardsPoint(*private_view_key * ED25519_BASEPOINT_POINT);
    (private_view_key, public_view_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::keys::PublicKey;
    use ciphersuite::group::GroupEncoding;

    /// Two fully specified secret scalars — canonical (high byte zero), no RNG anywhere in these vectors.
    const SECRET_A: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00";
    const SECRET_B: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f00";

    fn fixed_keypairs() -> (Curve25519Secret, Curve25519Secret, Curve25519PublicKey, Curve25519PublicKey) {
        let a = Curve25519Secret::from_hex(SECRET_A).expect("canonical scalar");
        let b = Curve25519Secret::from_hex(SECRET_B).expect("canonical scalar");
        let pa = Curve25519PublicKey::from_secret(&a);
        let pb = Curve25519PublicKey::from_secret(&b);
        (a, b, pa, pb)
    }

    /// The public keys the vectors below are stated over. Pinned so a change in `dalek-ff-group`'s scalar-to-point
    /// path shows up here rather than as an unexplained group-key mismatch.
    #[test]
    fn fixed_public_keys_are_frozen() {
        let (_, _, pa, pb) = fixed_keypairs();
        assert_eq!(pa.as_hex(), "616e237719716e25ead63d831f9117f79b5aa05af8be30ff0eddb3dc43e8bdcf");
        assert_eq!(pb.as_hex(), "af6302f1a901a870bf09273ec980939403e05cc90b2176a9ef901058b3d059bf");
        // A sorts before B, so `sort_pubkeys` is the identity here and the MuSig context is `"Musig" ‖ A ‖ B`.
        let mut sorted = [pb, pa];
        sort_pubkeys(&mut sorted);
        assert_eq!(sorted, [pa, pb]);
    }

    /// **The load-bearing vector of the serai migration.** Freezes the joint spend key produced by MuSig
    /// aggregation (via `ThresholdKeys::group_key`) over a fixed context and a fixed, sorted pair of public keys.
    ///
    /// The value below **moved** in the serai `next` swap, deliberately. `modular-frost 0.8`'s `dkg::musig` took
    /// a length-prefixed `&[u8]` context and derived its binding factors as `hash_to_F(b"musig", transcript)`;
    /// the standalone `musig` 0.6 crate takes a fixed `[u8; 32]` context and drops the `b"musig"` domain tag. The
    /// scheme is unchanged — the group key is still the sum of `bᵢ·Pᵢ` — but the transcript preimage is
    /// different, so every channel's 2-of-2 joint spend key changes. Grease has no live channels, which is the
    /// only reason that is acceptable. The pre-swap value was
    /// `2be132dccafba6aa928022244be1a8ddb707c7ac5c49653d530bf8f98b3ce1c3`.
    #[test]
    fn musig_group_key_is_frozen() {
        let (a, b, pa, pb) = fixed_keypairs();
        let sorted = [pa, pb];

        let keys = musig_2_of_2(&a, &sorted).expect("musig");
        assert_eq!(
            hex::encode(keys.group_key().to_bytes()),
            "d84486c8b988b72aacee390bb88bde734332d4c06a383f27874428f833ad7319"
        );

        // The counterparty, running the same aggregation over its own secret, must land on the same joint key.
        let peer_keys = musig_2_of_2(&b, &sorted).expect("musig");
        assert_eq!(peer_keys.group_key(), keys.group_key());
    }

    /// Freezes the Diffie-Hellman joint view key: `Blake2b512("MuSigViewKey" ‖ compress(s_a·P_b))` reduced wide,
    /// and its public point. Crosses `blake2 0.10` (bumped to the 0.11 rc generation by the flag day),
    /// `curve25519-dalek`'s point compression, and `dalek-ff-group`'s wide scalar reduction.
    #[test]
    fn musig_dh_viewkey_is_frozen() {
        let (a, b, pa, pb) = fixed_keypairs();

        let (private_view_key, public_view_key) = musig_dh_viewkey(&a, &pb);
        assert_eq!(
            hex::encode(private_view_key.to_bytes()),
            "bc26e2b8eaabe442e340ecb1257d639f64d7c581a2801f4ff90b10e927c27c09"
        );
        assert_eq!(
            hex::encode(public_view_key.to_bytes()),
            "98d67ed9ddeaedcd87506a35a28ecc62e0f8cca85ae1aa4467d25942ec49bec8"
        );

        // Both parties derive the same view key from the shared secret.
        let (peer_private, peer_public) = musig_dh_viewkey(&b, &pa);
        assert_eq!(peer_private.to_bytes(), private_view_key.to_bytes());
        assert_eq!(peer_public, public_view_key);
    }
}
