use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::cryptography::{Commit, HashCommitment256};
use crate::error::ReadError;
use crate::grease_protocol::utils::{read_group_element, write_group_element, Readable};
use crate::payment_channel::multisig_keyring::sort_pubkeys;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::wallet::errors::WalletError;
use ciphersuite::Ed25519;
use flexible_transcript::{DigestTranscript, SecureDigest, Transcript};
use log::*;
use modular_frost::sign::Writable;
use monero::Address;
use std::io::{Read, Write};
use thiserror::Error;

/// A trait for types that have a public key.
///
/// We return an owned copy of the key for convenience since the underlying type implements `Copy`.
pub trait HasPublicKey {
    fn public_key(&self) -> Curve25519PublicKey;
}

/// A trait for types that have a secret key.
///
/// We return a clone of the key for convenience. It will automatically be zeroized when it goes out of scope.
pub trait HasSecretKey {
    fn secret_key(&self) -> Curve25519Secret;
}

/// A trait that describes the behavior necessary for creating a multisignature Monero wallet.
///
/// This protocol assumes that information is shared over two rounds:
/// 1. Each party generates their wallet keys. One party (B) commits to their public key and shares it with the other party (A).
/// 2. A shares their public key with B.
/// 3. B shares their public key with A.
/// 4. A verifies that B's public key matches the commitment from step 1.
///
/// Both parties can now proceed to collaboratively create and sign multisignature transactions via the
/// `MultisigTransaction` trait.
pub trait LinkedMultisigWallets<D: SecureDigest>: HasPublicKey + HasRole {
    type SharedKeyType: HasPublicKey + HasRole + Writable + Commit<D> + Readable;

    /// Creates a commitment to our public key that can be shared with the peer. It includes the role that the peer
    /// plays so that this can also be verified later.
    fn commit_to_public_key(&self) -> <Self::SharedKeyType as Commit<D>>::Committed {
        self.shared_public_key().commit()
    }

    /// Return our shared public key information, which at minimum includes our public key and role.
    fn shared_public_key(&self) -> Self::SharedKeyType;

    /// Sets the peer's public key commitment.
    fn set_peer_public_key_commitment(&mut self, commitment: <Self::SharedKeyType as Commit<D>>::Committed);

    /// Retrieves the peer's public key commitment.
    fn peer_public_key_commitment(&self)
        -> Result<&<Self::SharedKeyType as Commit<D>>::Committed, MultisigWalletError>;

    /// Sets the peer's public key information, which at minimum includes their public key and role.
    fn set_peer_public_key(&mut self, public_key: Self::SharedKeyType) -> Result<(), MultisigWalletError>;

    /// Retrieves the peer's public key information, which at minimum includes their public key and role.
    fn peer_shared_public_key(&self) -> Result<&Self::SharedKeyType, MultisigWalletError>;

    /// A convenience method to retrieve the peer's public key.
    fn peer_public_key(&self) -> Result<Curve25519PublicKey, MultisigWalletError> {
        Ok(self.peer_shared_public_key()?.public_key())
    }

    /// A convenience method to retrieve both public keys sorted in lexicographical order.
    fn sorted_public_keys(&self) -> Result<[Curve25519PublicKey; 2], MultisigWalletError> {
        let mut pubkeys = [self.public_key(), self.peer_public_key()?];
        sort_pubkeys(&mut pubkeys);
        Ok(pubkeys)
    }

    /// Verifies that the peer's public key matches the committed value and that the roles are compatible.
    fn verify_peer_public_key(&self) -> Result<(), MultisigWalletError> {
        let peer_pubkey = self.peer_shared_public_key()?;
        if self.role() == peer_pubkey.role() {
            return Err(MultisigWalletError::IncompatibleRoles);
        }
        let commitment = self.peer_public_key_commitment()?;
        match peer_pubkey.verify(commitment) {
            true => {
                debug!(
                    "VALID: {} provided a public key that matches their commitment",
                    peer_pubkey.role()
                );
                Ok(())
            }
            false => Err(MultisigWalletError::IncorrectPublicKey),
        }
    }

    /// The Monero address associated with this multisignature wallet.
    fn shared_address(&self) -> Result<Address, MultisigWalletError>;
}

#[derive(Debug, Clone, Error)]
pub enum MultisigWalletError {
    #[error("Missing information: {0}")]
    MissingInformation(String),
    #[error("The provided public key does not match the committed value.")]
    IncorrectPublicKey,
    #[error("We cannot open a channel with both parties playing the same role")]
    IncompatibleRoles,
    #[error("Monero RPC wallet error: {0}")]
    MoneroWalletError(#[from] WalletError),
}

#[derive(Debug, Error)]
pub enum MultisigTxError {
    #[error("Transaction has not been prepared.")]
    NotPrepared,
    #[error("Multisignature pre-preparation step failed: {0}")]
    PreprepareError(String),
    #[error("Multisignature partial signing failed: {0}")]
    PartialSignError(String),
    #[error("Multisignature final signing failed: {0}")]
    FinalSignError(String),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SharedPublicKey {
    pub role: ChannelRole,
    pub public_key: Curve25519PublicKey,
}

impl SharedPublicKey {
    pub fn new(role: ChannelRole, public_key: Curve25519PublicKey) -> Self {
        Self { role, public_key }
    }

    pub fn public_key_ref(&self) -> &Curve25519PublicKey {
        &self.public_key
    }
}

impl Readable for SharedPublicKey {
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ReadError> {
        let role = ChannelRole::read(reader)?;
        let point = read_group_element::<Ed25519, _>(reader)
            .map_err(|e| ReadError::new("SharedPublicKey.public_key", e.to_string()))?;
        let public_key = Curve25519PublicKey::from(point);
        Ok(Self { role, public_key })
    }
}

impl HasPublicKey for SharedPublicKey {
    fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }
}

impl HasRole for SharedPublicKey {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl Writable for SharedPublicKey {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.role.write(writer)?;
        write_group_element::<Ed25519, _>(writer, &self.public_key.as_point())
    }
}

impl<D: SecureDigest + Send + Clone> Commit<D> for SharedPublicKey {
    type Committed = HashCommitment256<D>;
    type Transcript = DigestTranscript<D>;

    fn commit(&self) -> Self::Committed {
        let mut transcript = Self::Transcript::new(b"pubkey-t-m");
        transcript.append_message(b"role", self.role);
        transcript.append_message(b"my_pubkey", self.public_key.to_compressed().as_bytes());
        let commitment = transcript.challenge(b"merchant-public-key-commitment");
        let mut data = [0u8; 32];
        // The compiler guarantees that the output size of the hash function is at least 32 bytes.
        data.copy_from_slice(&commitment[0..32]);
        HashCommitment256::new(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::keys::{PublicKey, PublicKeyCommitment};
    use rand_core::OsRng;

    #[test]
    fn test_shared_public_key() {
        let (_sk, pk) = Curve25519PublicKey::keypair(&mut OsRng);
        let shared_key = SharedPublicKey::new(ChannelRole::Merchant, pk);
        let commitment: PublicKeyCommitment = shared_key.commit();

        let data = shared_key.serialize();
        let key2 = SharedPublicKey::read(&mut &data[..]).unwrap();

        assert_eq!(shared_key.role(), key2.role());
        assert_eq!(shared_key.public_key(), key2.public_key());
        assert_eq!(commitment, key2.commit());
    }
}
