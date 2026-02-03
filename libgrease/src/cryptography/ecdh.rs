//! ECDH shared secret derivation.
//!
//! This module provides a curve-agnostic ECDH function that derives a scalar shared secret
//! from a private key and peer's public key using domain separation.

use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use zeroize::Zeroizing;

/// Default domain separator for ECDH shared secret derivation.
pub const DEFAULT_ECDH_DOMAIN: &[u8] = b"ECDHSharedSecret";

/// Derive a shared secret scalar using ECDH with domain separation.
///
/// Computes the shared secret as:
/// 1. `P_s = secret * peer_pubkey` (ECDH shared point)
/// 2. `s = H2F(domain, P_s)` (hash to field element)
///
/// The result is wrapped in `Zeroizing` to ensure it is securely erased from memory when dropped.
pub fn ecdh<C: Ciphersuite, D: AsRef<[u8]>>(secret: &C::F, peer_pubkey: &C::G, domain: D) -> Zeroizing<C::F> {
    let shared_point = *peer_pubkey * *secret;
    let shared_secret = C::hash_to_F(domain.as_ref(), shared_point.to_bytes().as_ref());
    Zeroizing::new(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::Ed25519;

    #[test]
    fn ecdh_symmetric() {
        let mut rng = rand_core::OsRng;

        let alice_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let alice_pubkey = Ed25519::generator() * alice_secret;

        let bob_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let bob_pubkey = Ed25519::generator() * bob_secret;

        // Alice computes shared secret with Bob's public key
        let alice_shared = ecdh::<Ed25519, _>(&alice_secret, &bob_pubkey, DEFAULT_ECDH_DOMAIN);

        // Bob computes shared secret with Alice's public key
        let bob_shared = ecdh::<Ed25519, _>(&bob_secret, &alice_pubkey, DEFAULT_ECDH_DOMAIN);

        assert_eq!(*alice_shared, *bob_shared);
    }

    #[test]
    fn different_domains_produce_different_secrets() {
        let mut rng = rand_core::OsRng;

        let alice_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let bob_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let bob_pubkey = Ed25519::generator() * bob_secret;

        let secret_a = ecdh::<Ed25519, _>(&alice_secret, &bob_pubkey, b"domain_a");
        let secret_b = ecdh::<Ed25519, _>(&alice_secret, &bob_pubkey, b"domain_b");

        assert_ne!(*secret_a, *secret_b);
    }

    #[test]
    fn different_peers_produce_different_secrets() {
        let mut rng = rand_core::OsRng;

        let alice_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);

        let bob_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let bob_pubkey = Ed25519::generator() * bob_secret;

        let charlie_secret = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut rng);
        let charlie_pubkey = Ed25519::generator() * charlie_secret;

        let shared_with_bob = ecdh::<Ed25519, _>(&alice_secret, &bob_pubkey, DEFAULT_ECDH_DOMAIN);
        let shared_with_charlie = ecdh::<Ed25519, _>(&alice_secret, &charlie_pubkey, DEFAULT_ECDH_DOMAIN);

        assert_ne!(*shared_with_bob, *shared_with_charlie);
    }
}
