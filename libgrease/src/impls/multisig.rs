use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey, PublicKeyCommitment};
use crate::grease_protocol::multisig_wallet::{
    HasPublicKey, HasSecretKey, LinkedMultisigWallets, MultisigWalletError, SharedPublicKey,
};
use crate::payment_channel::{ChannelRole, HasRole};
use blake2::Blake2b512;
use rand_core::{CryptoRng, RngCore};

/// A struct to manage the key information for a multisig wallet.
///
/// This struct is designed to be used in the context of a payment channel, where each party has a role
/// (customer or merchant) and needs to manage their own keys as well as information about the peer's keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultisigWalletKeyRing {
    pub role: ChannelRole,
    pub partial_spend_key: Curve25519Secret,
    pub public_key: Curve25519PublicKey,
    pub peer_commitment: Option<PublicKeyCommitment>,
    pub peer_public_key: Option<SharedPublicKey>,
}

impl MultisigWalletKeyRing {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole) -> Self {
        let (partial_spend_key, public_key) = Curve25519PublicKey::keypair(rng);
        Self { role, partial_spend_key, public_key, peer_commitment: None, peer_public_key: None }
    }
}

impl HasRole for MultisigWalletKeyRing {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl HasPublicKey for MultisigWalletKeyRing {
    fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }
}

impl HasSecretKey for MultisigWalletKeyRing {
    fn secret_key(&self) -> Curve25519Secret {
        self.partial_spend_key.clone()
    }
}

impl LinkedMultisigWallets<Blake2b512> for MultisigWalletKeyRing {
    type SharedKeyType = SharedPublicKey;

    fn shared_public_key(&self) -> Self::SharedKeyType {
        SharedPublicKey { role: self.role, public_key: self.public_key }
    }

    fn set_peer_public_key_commitment(&mut self, commitment: PublicKeyCommitment) {
        self.peer_commitment = Some(commitment);
    }

    fn peer_public_key_commitment(&self) -> Result<&PublicKeyCommitment, MultisigWalletError> {
        self.peer_commitment
            .as_ref()
            .ok_or(MultisigWalletError::MissingInformation("Peer public key commitment".into()))
    }

    fn set_peer_public_key(&mut self, public_key: Self::SharedKeyType) {
        self.peer_public_key = Some(public_key);
    }

    fn peer_shared_public_key(&self) -> Result<&Self::SharedKeyType, MultisigWalletError> {
        self.peer_public_key.as_ref().ok_or(MultisigWalletError::MissingInformation("Peer public key".into()))
    }
}
