//! Implementation of 2P-CLRAS for Curve 25519 in particular, for use in Monero payment channels.

use crate::crypto::cas::{
    ConsecutiveAdaptorSignature, PreSignature, Signature, Statement, StatementWitnessProof, Witness,
};
use crate::crypto::clras::Clras2P;
use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::crypto::traits::PublicKey;
use blake::Blake;
use curve25519_dalek::Scalar;

/// The Monero witness is used in payment channels to reconstruct the spending key for the commitment transaction. It
/// is updated every time the balance is updated.
pub struct MoneroWitness(Curve25519Secret);

impl Witness for MoneroWitness {
    type S = MoneroStatement;

    fn generate_statement(&self) -> Self::S {
        let pub_key = Curve25519PublicKey::from_secret(&self.0);
        MoneroStatement(pub_key)
    }

    fn as_scalar(&self) -> &Scalar {
        self.0.as_scalar()
    }

    fn from_scalar(scalar: Scalar) -> Self {
        let key = Curve25519Secret::from(scalar);
        Self(key)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MoneroStatement(Curve25519PublicKey);

impl Statement for MoneroStatement {
    fn as_public_key(&self) -> &Curve25519PublicKey {
        &self.0
    }

    fn from_public_key(key: Curve25519PublicKey) -> Self {
        Self(key)
    }
}

pub struct SchnorrProof {
    pub public_nonce: Curve25519PublicKey,
    pub s: Scalar,
}

pub type MoneroVCOFProof = StatementWitnessProof<SchnorrProof>;

pub struct MoneroCas;

impl ConsecutiveAdaptorSignature for MoneroCas {
    type W = MoneroWitness;

    fn generate_keypair(&mut self) -> (Curve25519Secret, Curve25519PublicKey) {
        Curve25519PublicKey::keypair(&mut rand::rng())
    }
    fn hash_to_scalar<B: AsRef<[u8]>>(
        &self,
        message: B,
        nonce: &Curve25519PublicKey,
        public_key: &Curve25519PublicKey,
    ) -> Scalar {
        let keys = [public_key.clone()];
        hash_to_scalar(b"MoneroCAS", message, nonce, &keys)
    }
}

pub struct MoneroClras2P {
    secret_key: Curve25519Secret,
    public_key: Curve25519PublicKey,
}

impl MoneroClras2P {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let (secret_key, public_key) = Curve25519PublicKey::keypair(&mut rng);
        Self { secret_key, public_key }
    }
}

impl Clras2P for MoneroClras2P {
    type Cas = MoneroCas;

    fn hash_to_scalar<B: AsRef<[u8]>>(
        &self,
        data: B,
        nonce: &Curve25519PublicKey,
        ring: &[Curve25519PublicKey],
    ) -> Scalar {
        hash_to_scalar(b"MoneroCLRAS2P", data, nonce, ring)
    }

    fn generate_public_nonce(
        &self,
        secret_nonce: &Curve25519Secret,
        ring: &[Curve25519PublicKey],
    ) -> Curve25519PublicKey {
        todo!()
    }

    fn pre_partial_sign(&self, secret_nonce: &Scalar, challenge: &Scalar, ring: &[Curve25519PublicKey]) -> Signature {
        todo!()
    }

    fn pre_signature_verify<B: AsRef<[u8]>>(
        &self,
        pre_signature: &PreSignature,
        message: B,
        statement: &<<Self::Cas as ConsecutiveAdaptorSignature>::W as Witness>::S,
        ring: &[Curve25519PublicKey],
    ) -> bool {
        todo!()
    }

    fn verify<B: AsRef<[u8]>>(&self, signature: &Signature, message: B, ring: &[Curve25519PublicKey]) -> bool {
        todo!()
    }
}

fn hash_to_scalar<B: AsRef<[u8]>>(
    domain: &[u8],
    message: B,
    nonce: &Curve25519PublicKey,
    keys: &[Curve25519PublicKey],
) -> Scalar {
    let mut hasher = Blake::new(512).expect("Should be able to create Blake instance");
    hasher.update(domain);
    hasher.update(nonce.as_compressed().as_bytes());
    assert!(
        keys.len() < 265,
        "The ring size should be less than 256. Larger rings are not supported."
    );
    if keys.len() > 1 {
        hasher.update(&[keys.len() as u8])
    }
    for key in keys {
        hasher.update(key.as_compressed().as_bytes());
    }
    hasher.update(message.as_ref());
    let mut hash = [0u8; 64];
    hasher.finalise(&mut hash);
    Scalar::from_bytes_mod_order_wide(&hash)
}
