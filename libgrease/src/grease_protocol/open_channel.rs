use crate::adapter_signature::AdaptedSignature;
use crate::crypto::dleq::Dleq;
use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::crypto::shard_encryption::EncryptedShard;
use crate::crypto::witness::InitialShards;
use crate::crypto::Commit;
use crate::error::ReadError;
use crate::grease_protocol::error::WitnessError;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use ciphersuite::Ed25519;
use flexible_transcript::SecureDigest;
use modular_frost::curve::Curve as FrostCurve;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use thiserror::Error;

pub trait MultisigWalletKeys: Sized + HasRole + Writable {
    /// The subset of the information in this data structure that is shared with the peer.
    type SharedWalletInfo: HasRole + Clone + Writable;
    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole) -> Self;
    fn secret(&self) -> &Curve25519Secret;
    fn public_key(&self) -> &Curve25519PublicKey;
    fn shared_info(&self) -> Self::SharedWalletInfo;
}

pub trait ReadSharedWalletInfo: Sized {
    fn read<R: Read>(reader: &mut R) -> Result<Self, OpenProtocolError>;
}

pub trait HasPublicKey {
    fn public_key(&self) -> &Curve25519PublicKey;
}

pub trait HasSecretKey {
    fn secret_key(&self) -> &Curve25519Secret;
}

pub trait ShardHandler<C, D>: HasRole + HasSecretKey + Sized
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
    /// A struct that, at the very minimum commits to the merchant's multisig wallet public key.
    type SharedWalletInfo: Commit<D> + ReadSharedWalletInfo + HasRole + HasPublicKey;

    fn shared_wallet_info(&self) -> Self::SharedWalletInfo;
    fn peer_shared_wallet_info(&self) -> Option<&Self::SharedWalletInfo>;
    fn set_shared_wallet_info(&mut self, info: Self::SharedWalletInfo);
    fn read_shared_wallet_info<R: Read>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let peer_info = Self::SharedWalletInfo::read(reader)?;
        if peer_info.role() == self.role() {
            return Err(OpenProtocolError::InvalidDataFromPeer(format!(
                "Expected {} shared wallet info",
                self.role().other()
            )));
        }
        self.set_shared_wallet_info(peer_info);
        Ok(())
    }

    fn generate_initial_shards<Q, R>(&mut self, rng: &mut R) -> Result<(), OpenProtocolError>
    where
        R: RngCore + CryptoRng,
        Q: Dleq<C>,
    {
        let witness0 = self.secret_key().as_scalar();
        let initial_shards = InitialShards::new(rng, self.role(), witness0)?;
        self.set_initial_shards(initial_shards);
        Ok(())
    }

    fn set_initial_shards(&mut self, shards: InitialShards<C, Ed25519>);
    fn initial_shards(&self) -> Option<&InitialShards<C, Ed25519>>;
    fn set_kes_pubkey(&mut self, kes_pubkey: C::G);
    fn kes_pubkey(&self) -> Option<&C::G>;

    fn encrypt_shards<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(EncryptedShard<Ed25519>, EncryptedShard<C>), OpenProtocolError> {
        let other_role = self.role().other().to_string();
        let shared_info = self
            .peer_shared_wallet_info()
            .ok_or_else(|| OpenProtocolError::MissingInformation(format!("{other_role} shared wallet")))?;
        if shared_info.role() == self.role() {
            return Err(OpenProtocolError::InvalidDataFromPeer(format!(
                "encrypt_shards expected wallet info shared from a {other_role}"
            )));
        }
        let pubkey = shared_info.public_key();
        let shards =
            self.initial_shards().ok_or_else(|| OpenProtocolError::MissingInformation("Initial shards".into()))?;
        if shards.role() != self.role() {
            return Err(OpenProtocolError::InvalidDataFromPeer(format!(
                "encrypt_shards expected initial shards from a {}",
                self.role()
            )));
        }
        let kes_pubkey =
            self.kes_pubkey().ok_or_else(|| OpenProtocolError::MissingInformation("KES public key".into()))?;
        let (peer_shard, kes_shard) = shards.encrypt_shards(&pubkey.as_point(), &kes_pubkey, rng)?;
        Ok((peer_shard, kes_shard))
    }
}

pub trait AdapterSignatureHandler: HasRole + HasSecretKey {
    fn generate_adapter_signature_offset<R: RngCore + CryptoRng>(&mut self, rng: &mut R);
    fn adapter_signature_offset(&self) -> Option<&XmrScalar>;
    fn adapter_signature_message(&self) -> &'static str {
        "Grease channel opening"
    }
    fn new_adapter_signature<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<AdaptedSignature<Ed25519>, OpenProtocolError> {
        let offset = self
            .adapter_signature_offset()
            .ok_or_else(|| OpenProtocolError::MissingInformation("Adapter signature offset".into()))?;
        let secret = self.secret_key().as_scalar();
        let signature = AdaptedSignature::<Ed25519>::sign(secret, offset, self.adapter_signature_message(), rng);
        Ok(signature)
    }
}

pub trait MerchantOpenProtocol<C, D>: ShardHandler<C, D> + AdapterSignatureHandler + Sized
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
    type WalletKeys: MultisigWalletKeys;
    /// Start a new channel opening protocol for the merchant.
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    fn wallet_info(&self) -> &Self::WalletKeys;

    fn commit_to_shared_wallet_info(&self) -> <Self::SharedWalletInfo as Commit<D>>::Committed {
        self.shared_wallet_info().commit()
    }
}

pub trait CustomerOpenProtocol<C, D>: ShardHandler<C, D> + AdapterSignatureHandler + Sized
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
    type WalletKeys: MultisigWalletKeys;

    /// Start a new channel opening protocol for the customer.
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
    fn read_wallet_commitment<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError>;
    fn wallet_info(&self) -> &Self::WalletKeys;
    fn verify_merchant_public_key(&self) -> Result<(), OpenProtocolError>;
}

pub trait KesOpenProtocol {
    /// Create a new KES open protocol instance with the given keypair.
    /// `secret` is the KES secret key corresponding to its identifying `public_key`.
    fn new_with_keypair(secret: Curve25519Secret, public_key: Curve25519PublicKey) -> Self;
}

#[derive(Debug, Error)]
pub enum OpenProtocolError {
    #[error("A commitment is invalid: {0}")]
    InvalidCommitment(String),
    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),
    #[error("Witness error: {0}")]
    WitnessError(#[from] WitnessError),
    #[error("Could not provide result because the following information is missing: {0}")]
    MissingInformation(String),
    #[error("Could not deserialize a binary data structure: {0}")]
    ReadError(#[from] ReadError),
}
