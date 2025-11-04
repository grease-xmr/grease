use crate::error::ReadError;
use crate::grease_protocol::utils::{write_field_element, write_group_element};
use ciphersuite::group::ff::Field;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use log::*;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use zeroize::Zeroize;

pub struct KesPoK<C: Ciphersuite> {
    pub shard_pok: SchnorrPoK<C>,
    pub private_key_pok: SchnorrPoK<C>,
}

impl<C: Ciphersuite> KesPoK<C> {
    /// Prove that the possessor of `private_key` knows `shard`.
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, shard: &C::F, private_key: &C::F) -> Self {
        let shard_pok = SchnorrPoK::<C>::prove(rng, shard);
        let private_key_pok = SchnorrPoK::prove(rng, private_key);
        Self { shard_pok, private_key_pok }
    }

    pub fn verify(&self, shard_pubkey: &C::G, kes_pubkey: &C::G) -> bool {
        let pk_valid = self.private_key_pok.verify(kes_pubkey);
        let result_pk = if pk_valid { "KES knows the private key" } else { "KES does NOT know the private key" };
        let shard_valid = self.shard_pok.verify(shard_pubkey);
        let result_shard = if shard_valid { "KES knows the shard value" } else { "KES does NOT know the shard value" };
        let result = pk_valid && shard_valid;
        if result {
            debug!("VALID: {result_pk} AND {result_shard}");
        } else {
            warn!("INVALID KES PoK verification: {result_pk} AND {result_shard}");
        };
        result
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let shard_pok = SchnorrPoK::<C>::read(reader)?;
        let private_key_pok = SchnorrPoK::<C>::read(reader)?;
        Ok(Self { shard_pok, private_key_pok })
    }
}

impl<C: Ciphersuite> Writable for KesPoK<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.shard_pok.write(writer)?;
        self.private_key_pok.write(writer)?;
        Ok(())
    }
}

pub struct SchnorrPoK<C: Ciphersuite> {
    pub_nonce: C::G,
    s: C::F,
}

impl<C: Ciphersuite> SchnorrPoK<C> {
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
        let rhs = self.pub_nonce + *public_key * Self::challenge(&self.pub_nonce, public_key);
        lhs == rhs
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let pub_nonce = crate::grease_protocol::utils::read_group_element::<C, R>(reader)
            .map_err(|e| ReadError::new("SchnorrPoK.pub_nonce", e.to_string()))?;
        if pub_nonce.is_identity().into() {
            return Err(ReadError::new(
                "SchnorrPoK.pub_nonce",
                "public nonce cannot be the identity element".to_string(),
            ));
        }
        let s = crate::grease_protocol::utils::read_field_element::<C, R>(reader)
            .map_err(|e| ReadError::new("SchnorrPoK.s", e.to_string()))?;
        Ok(Self { pub_nonce, s })
    }
}

impl<C: Ciphersuite> Writable for SchnorrPoK<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        write_group_element::<C, W>(writer, &self.pub_nonce)?;
        write_field_element::<C, W>(writer, &self.s)?;
        Ok(())
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
        let data = pok.serialize();
        let pok = KesPoK::<Ed25519>::read(&mut &data[..]).unwrap();
        assert!(pok.verify(&sigma_pubkey, &kes_pubkey));
        let invalid_kes_pubkey = kes_pubkey + Ed25519::generator();
        assert!(!pok.verify(&sigma_pubkey, &invalid_kes_pubkey));
    }
}
