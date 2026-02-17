use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use blake2::Blake2b512;
use ciphersuite::Ed25519;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use dalek_ff_group::{EdwardsPoint, Scalar};
use digest::Digest;
use modular_frost::dkg::musig::musig;
use modular_frost::dkg::DkgError;
use modular_frost::ThresholdKeys;
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

pub fn musig_2_of_2(
    secret: &Curve25519Secret,
    sorted_pubkeys: &[Curve25519PublicKey; 2],
) -> Result<ThresholdKeys<Ed25519>, DkgError<()>> {
    let context = musig_context(sorted_pubkeys);
    let secret = Zeroizing::new(Scalar(*secret.as_dalek_scalar()));
    let pubkeys: [EdwardsPoint; 2] = [sorted_pubkeys[0].as_point(), sorted_pubkeys[1].as_point()];
    let core = musig(&context[..], &secret, &pubkeys)?;
    Ok(ThresholdKeys::new(core))
}

pub fn musig_dh_viewkey(secret: &Curve25519Secret, other: &Curve25519PublicKey) -> (Zeroizing<Scalar>, EdwardsPoint) {
    let shared = *other.as_point() * secret.as_dalek_scalar();
    let hashed = Blake2b512::new().chain_update(b"MuSigViewKey").chain_update(shared.compress().as_bytes()).finalize();
    let mut bytes = [0u8; 64];
    bytes[..].copy_from_slice(hashed.as_slice());
    let private_view_key = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&bytes));
    let public_view_key = EdwardsPoint(private_view_key.0 * ED25519_BASEPOINT_POINT);
    (private_view_key, public_view_key)
}
