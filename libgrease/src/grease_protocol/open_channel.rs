use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::cryptography::Commit;
use crate::error::ReadError;
use crate::grease_protocol::error::DleqError;
use crate::grease_protocol::kes::KesClient;
use crate::grease_protocol::multisig_wallet::{LinkedMultisigWallets, MultisigWalletError};
use crate::grease_protocol::utils::Readable;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::Ed25519;
use flexible_transcript::SecureDigest;
use log::{debug, trace};
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use std::io::Read;
use thiserror::Error;

/// Provides information about a peer in the open channel protocol.
pub trait PeerInfo<C>
where
    C: FrostCurve,
    Ed25519: Dleq<C>,
{
    fn peer_dleq_proof(&self) -> Option<&DleqProof<C, Ed25519>>;
    fn peer_public_key(&self) -> Option<Curve25519PublicKey>;
    fn peer_adapted_signature(&self) -> Option<&AdaptedSignature<Ed25519>>;

    /// Verify that the adaptor signature offset given to the KES.
    ///
    /// Each peer needs to verify that the value that the counterparty gave to the KES is in fact ω0.
    ///
    /// This is done in three steps:
    /// 1. Verify the DLEQ proof provided by the peer. This proves that $T_0 = ω_0.G$ on the KES' curve is the same as
    ///    $S_0 = ω_0.G$ on Ed25519.
    /// 2. Verify that the adapted signature, (ŝ, R, Q) _would_ be a valid signature for the channel closing transaction
    ///    _if_ we knew ω (where Q = ω.G), since this would give us (s, R), the signature we need.
    /// 2. Since we've established that Q blinds ω, if S0 == Q, then we know that the peer provided the correct offset
    ///    to the KES.
    fn verify_adapter_sig_offset<B: AsRef<[u8]>>(&self, adapter_sig_msg: B) -> Result<(), OpenProtocolError> {
        let sig = self
            .peer_adapted_signature()
            .ok_or_else(|| OpenProtocolError::MissingInformation("Adapted signature".into()))?;
        let peer_pubkey =
            self.peer_public_key().ok_or_else(|| OpenProtocolError::MissingInformation("Peer public key".into()))?;
        if !sig.verify(&peer_pubkey.as_point(), adapter_sig_msg) {
            return Err(OpenProtocolError::InvalidDataFromPeer(
                "Adapted signature verification failed".into(),
            ));
        }
        trace!("VALID: Peer's adapted signature is valid.");
        let proof = self.peer_dleq_proof().ok_or_else(|| OpenProtocolError::MissingInformation("DLEQ proof".into()))?;
        proof.verify()?;
        trace!("VALID: Peer's DLEQ proof is valid.");

        let q_ed25519 = sig.adapter_commitment();
        if proof.xmr_point != q_ed25519 {
            return Err(OpenProtocolError::InvalidDataFromPeer(
                "DLEQ proof XMR point does not match adapted signature commitment".into(),
            ));
        }
        trace!("VALID: Peer's DLEQ proof XMR point matches adapted signature commitment.");
        debug!("✅ Adapter signature offset verified successfully.");
        Ok(())
    }
}

pub trait OpenProtocol<C, D>: Sized + HasRole
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
    type MultisigWallet: LinkedMultisigWallets<D>;
    type KesClient: KesClient<C>;

    /// Start a new channel opening protocol.
    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole) -> Self;

    /// Initialize the KES client associated with [`Self::KesClient`].
    fn initialize_kes_client<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        kes_pubkey: C::G,
    ) -> Result<(), OpenProtocolError>;

    fn kes_client(&self) -> Result<&Self::KesClient, OpenProtocolError>;

    /// Provide access to the multisig wallet keys.
    fn wallet(&self) -> &Self::MultisigWallet;

    /// Provide mutable access to the multisig wallet keys.
    fn wallet_mut(&mut self) -> &mut Self::MultisigWallet;

    /// Read the peer's shared public key (includes role) from the given reader and store it.
    fn read_peer_shared_public_key<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let shared_pubkey = <Self::MultisigWallet as LinkedMultisigWallets<D>>::SharedKeyType::read(reader)?;
        if shared_pubkey.role() == self.role() {
            return Err(OpenProtocolError::InvalidDataFromPeer(format!(
                "Peer public key has incompatible role. It should be {} but received {}",
                self.role().other(),
                shared_pubkey.role()
            )));
        }
        self.wallet_mut().set_peer_public_key(shared_pubkey);
        Ok(())
    }

    /// Read the peer's adapted signature from the given reader and store it.
    fn read_peer_adapted_signature<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let adapted_signature = AdaptedSignature::<Ed25519>::read(reader)?;
        self.set_peer_adapted_signature(adapted_signature);
        Ok(())
    }

    /// Set the peer's adapted signature.
    ///
    /// This is usually not called directly, but rather through [`read_peer_adapted_signature`].
    fn set_peer_adapted_signature(&mut self, adapted_signature: AdaptedSignature<Ed25519>);

    /// Read the peer's DLEQ proof from the given reader and store it.
    fn read_peer_dleq_proof<R: Read>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let dleq_proof = DleqProof::<C, Ed25519>::read(reader)?;
        self.set_peer_dleq_proof(dleq_proof);
        Ok(())
    }

    /// Set the peer's DLEQ proof.
    ///
    /// This is usually not called directly, but rather through [`read_peer_dleq_proof`].
    fn set_peer_dleq_proof(&mut self, dleq_proof: DleqProof<C, Ed25519>);
}

/// An extension trait for Merchant-specific requirements for the Open Channel protocol.
pub trait MerchantOpenProtocol<C, D>: OpenProtocol<C, D>
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
}

pub trait CustomerOpenProtocol<C, D>: OpenProtocol<C, D>
where
    C: FrostCurve,
    D: SecureDigest,
    Ed25519: Dleq<C>,
{
    fn read_wallet_commitment<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let commitment =
            <<<Self as OpenProtocol<C, D>>::MultisigWallet as LinkedMultisigWallets<D>>::SharedKeyType as Commit<D>>::Committed::read(reader)?;
        self.wallet_mut().set_peer_public_key_commitment(commitment);
        Ok(())
    }

    fn verify_merchant_public_key(&self) -> Result<(), OpenProtocolError> {
        let merchant_pubkey = self.wallet().peer_shared_public_key()?;
        let commitment = self.wallet().peer_public_key_commitment()?;
        match merchant_pubkey.verify(commitment) {
            true => Ok(()),
            false => Err(OpenProtocolError::InvalidDataFromPeer(
                "Merchant public key does not match commitment".into(),
            )),
        }
    }
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
    #[error("AdapterSigOffset error: {0}")]
    AdapterSigOffsetError(#[from] DleqError),
    #[error("The provided KES public key is invalid for the given curve.")]
    InvalidKesPublicKey,
    #[error("Could not provide result because the {0} is missing.")]
    MissingInformation(String),
    #[error("Multisig wallet error: {0}")]
    MultisigWalletError(#[from] MultisigWalletError),
    #[error("Could not deserialize a binary data structure: {0}")]
    ReadError(#[from] ReadError),
}
