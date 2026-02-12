use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey, PublicKeyCommitment};
use crate::grease_protocol::multisig_wallet::{
    HasPublicKey, HasSecretKey, LinkedMultisigWallets, MultisigWalletError, SharedPublicKey,
};
use crate::payment_channel::multisig_keyring::{musig_2_of_2, musig_dh_viewkey, sort_pubkeys};
use crate::payment_channel::{ChannelRole, HasRole};
use blake2::Blake2b512;
use monero::{Address, Network, PrivateKey, ViewPair};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A struct to manage the key information for a multisig wallet.
///
/// This struct is used when negotiating the multisig wallet protocol (by virtue of all the Optional fields).
///Once the protocol is complete, the wallet information can `finalized` into a  `MultisigWalletKeyring` that contains
/// all the necessary information to manage the multisig wallet and create transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigWalletKeyNegotiation {
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub network: Network,
    /// The URL for a monero RPC daemon.
    pub rpc_url: String,
    pub role: ChannelRole,
    pub partial_spend_key: Curve25519Secret,
    pub public_key: Curve25519PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_commitment: Option<PublicKeyCommitment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_public_key: Option<SharedPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sorted_pubkeys: Option<[Curve25519PublicKey; 2]>,
    #[serde(skip)]
    pub joint_private_view_key: Option<Curve25519Secret>,
    #[serde(skip)]
    pub joint_public_view_key: Option<Curve25519PublicKey>,
    #[serde(skip)]
    pub joint_public_spend_key: Option<Curve25519PublicKey>,
    pub birthday: u64,
    pub known_outputs: Vec<Vec<u8>>,
}

impl MultisigWalletKeyNegotiation {
    pub fn new(
        role: ChannelRole,
        network: Network,
        partial_spend_key: Curve25519Secret,
        rpc_url: impl Into<String>,
    ) -> Self {
        let public_key = Curve25519PublicKey::from_secret(&partial_spend_key);
        Self {
            network,
            role,
            rpc_url: rpc_url.into(),
            partial_spend_key,
            public_key,
            peer_commitment: None,
            peer_public_key: None,
            sorted_pubkeys: None,
            joint_private_view_key: None,
            joint_public_view_key: None,
            joint_public_spend_key: None,
            birthday: 0,
            known_outputs: vec![],
        }
    }

    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        role: ChannelRole,
        network: Network,
        rpc_url: impl Into<String>,
    ) -> Self {
        let partial_spend_key = Curve25519Secret::random(rng);
        Self::new(role, network, partial_spend_key, rpc_url)
    }

    pub fn address(&self) -> Option<Address> {
        let jpub = self.joint_public_spend_key.as_ref()?;
        let jpriv = self.joint_private_view_key.as_ref()?;
        let spend = monero::PublicKey { point: jpub.to_compressed() };
        let view = PrivateKey { scalar: *jpriv.as_dalek_scalar() };
        let keys = ViewPair { spend, view };
        Some(Address::from_viewpair(self.network, &keys))
    }

    fn calculate_computed_fields(&mut self) -> Result<(), MultisigWalletError> {
        let public_key = self.peer_public_key()?;
        let (jprv_vk, j_pub_vk) = musig_dh_viewkey(&self.partial_spend_key, &public_key);
        let mut pubkeys = [self.public_key(), public_key];
        sort_pubkeys(&mut pubkeys);
        let musig_keys =
            musig_2_of_2(&self.partial_spend_key, &pubkeys).map_err(|_| MultisigWalletError::IncorrectPublicKey)?;
        self.joint_private_view_key = Some(Curve25519Secret::from(jprv_vk.0));
        self.joint_public_view_key = Some(Curve25519PublicKey::from(j_pub_vk));
        self.joint_public_spend_key = Some(Curve25519PublicKey::from(musig_keys.group_key()));
        Ok(())
    }
}

impl HasRole for MultisigWalletKeyNegotiation {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl HasPublicKey for MultisigWalletKeyNegotiation {
    fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }
}

impl HasSecretKey for MultisigWalletKeyNegotiation {
    fn secret_key(&self) -> Curve25519Secret {
        self.partial_spend_key.clone()
    }
}

impl LinkedMultisigWallets<Blake2b512> for MultisigWalletKeyNegotiation {
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

    fn set_peer_public_key(&mut self, public_key: Self::SharedKeyType) -> Result<(), MultisigWalletError> {
        self.peer_public_key = Some(public_key);
        // Set the other fields that can be derived from the peer's public key
        self.calculate_computed_fields()?;
        Ok(())
    }

    fn peer_shared_public_key(&self) -> Result<&Self::SharedKeyType, MultisigWalletError> {
        self.peer_public_key.as_ref().ok_or(MultisigWalletError::MissingInformation("Peer public key".into()))
    }

    fn shared_address(&self) -> Result<Address, MultisigWalletError> {
        self.address()
            .ok_or_else(|| MultisigWalletError::MissingInformation("Peer public key or joint keys not set".into()))
    }
}
