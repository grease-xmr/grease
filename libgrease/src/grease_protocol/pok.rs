use ciphersuite::group::ff::Field;
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub struct KesPoK<C: Ciphersuite> {
    pub shard_pok: SchnorrPoK<C>,
    pub private_key_pok: SchnorrPoK<C>,
}

impl<C: Ciphersuite> KesPoK<C> {
    /// Prove that the possessor of `private_key` knows both `sigma_1`.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, shard: &C::F, private_key: &C::F) -> Self {
        let shard_pok = SchnorrPoK::<C>::prove(rng, shard);
        let private_key_pok = SchnorrPoK::prove(rng, private_key);
        Self { shard_pok, private_key_pok }
    }

    pub fn verify(&self, sigma_pubkey: &C::G, kes_pubkey: &C::G) -> bool {
        self.private_key_pok.verify(kes_pubkey) && self.shard_pok.verify(sigma_pubkey)
    }
}

pub struct SchnorrPoK<C: Ciphersuite> {
    pub_nonce: C::G,
    s: C::F,
}

impl<C: Ciphersuite> SchnorrPoK<C> {
    #[allow(non_snake_case)]
    fn challenge(pub_nonce: &C::G, pub_key: &C::G) -> C::F {
        let msg = [pub_nonce.to_bytes().as_ref(), pub_key.to_bytes().as_ref()].concat();
        C::hash_to_F(b"SchnorrPoK", &msg)
    }

    /// Prove that the possessor of `private_key` knows `sigma_1`.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, secret: &C::F) -> Self {
        let mut nonce = C::F::random(rng);
        let pub_nonce = C::generator() * nonce;
        let pub_key = C::generator() * secret;
        let s = nonce + *secret * Self::challenge(&pub_nonce, &pub_key);
        nonce.zeroize();
        Self { pub_nonce, s }
    }

    pub fn verify(&self, public_key: &C::G) -> bool {
        let lhs = C::generator() * self.s;
        let rhs = self.pub_nonce + *public_key * Self::challenge(&self.pub_nonce, &public_key);
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::Ed25519;

    #[test]
    fn schnorr_pok_on_ed25519() {
        let mut rng = rand_core::OsRng;
        let secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let public_key = Ed25519::generator() * &secret;
        let pok = SchnorrPoK::<Ed25519>::prove(&mut rng, &secret);
        assert!(pok.verify(&public_key));
        let invalid_pubkey = public_key + Ed25519::generator();
        assert!(!pok.verify(&invalid_pubkey));
    }

    #[test]
    fn kes_pok_on_ed25519() {
        let mut rng = rand_core::OsRng;
        let shard = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let private_key = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let sigma_pubkey = Ed25519::generator() * &shard;
        let kes_pubkey = Ed25519::generator() * &private_key;
        let pok = KesPoK::<Ed25519>::prove(&mut rng, &shard, &private_key);
        assert!(pok.verify(&sigma_pubkey, &kes_pubkey));
        let invalid_kes_pubkey = kes_pubkey + Ed25519::generator();
        assert!(!pok.verify(&sigma_pubkey, &invalid_kes_pubkey));
    }
}
