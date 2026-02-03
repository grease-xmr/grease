use crate::cryptography::keys::{Curve25519PublicKey, PublicKeyCommitment};
use crate::grease_protocol::multisig_wallet::{
    HasPublicKey, LinkedMultisigWallets, MultisigWalletError, SharedPublicKey,
};
use crate::grease_protocol::utils::Readable;
use crate::payment_channel::{ChannelRole, HasRole};
use blake2::Blake2b512;
use modular_frost::sign::Writable;
use std::fmt;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during multisig wallet setup.
#[derive(Debug, Clone, Error)]
pub enum MultisigSetupError {
    #[error("Invalid state transition: cannot {action} from {state} state")]
    InvalidStateTransition { state: String, action: &'static str },
    #[error("Commitment verification failed: the peer's public key does not match their commitment")]
    CommitmentMismatch,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Protocol timed out waiting for peer response")]
    Timeout,
    #[error("Missing required data: {0}")]
    MissingData(String),
    #[error("Wallet has wrong role for this setup type")]
    WrongRole,
}

impl From<MultisigWalletError> for MultisigSetupError {
    fn from(e: MultisigWalletError) -> Self {
        match e {
            MultisigWalletError::IncompatibleRoles => MultisigSetupError::WrongRole,
            MultisigWalletError::IncorrectPublicKey => MultisigSetupError::CommitmentMismatch,
            MultisigWalletError::MissingInformation(s) => MultisigSetupError::MissingData(s),
        }
    }
}

// ============================================================================
// Stage Enums - Role-specific stages make invalid states unrepresentable
// ============================================================================

/// Merchant-specific stages. The merchant flow is:
/// `Initialized -> CommitmentSent -> AwaitingPeerKey -> Complete`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerchantStage {
    /// Keys generated, ready to send commitment.
    Initialized,
    /// Commitment sent, waiting for customer's key.
    CommitmentSent,
    /// Received customer's key, ready to send our key and complete.
    AwaitingPeerKey,
    /// Setup successful.
    Complete,
    /// Setup failed.
    Aborted,
}

impl fmt::Display for MerchantStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized => write!(f, "Initialized"),
            Self::CommitmentSent => write!(f, "CommitmentSent"),
            Self::AwaitingPeerKey => write!(f, "AwaitingPeerKey"),
            Self::Complete => write!(f, "Complete"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

/// Customer-specific stages. The customer flow is:
/// `AwaitingPeerCommitment -> AwaitingPeerKey -> AwaitingVerification -> Complete`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomerStage {
    /// Waiting for merchant's commitment.
    AwaitingPeerCommitment,
    /// Received commitment, ready to send key and await merchant's key.
    AwaitingPeerKey,
    /// Received merchant's key, ready to verify commitment.
    AwaitingVerification,
    /// Setup successful.
    Complete,
    /// Setup failed.
    Aborted,
}

impl fmt::Display for CustomerStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingPeerCommitment => write!(f, "AwaitingPeerCommitment"),
            Self::AwaitingPeerKey => write!(f, "AwaitingPeerKey"),
            Self::AwaitingVerification => write!(f, "AwaitingVerification"),
            Self::Complete => write!(f, "Complete"),
            Self::Aborted => write!(f, "Aborted"),
        }
    }
}

// ============================================================================
// Common Trait - Shared interface for both setup types
// ============================================================================

/// Common interface for multisig wallet setup state machines.
///
/// Implementors also provide `public_key() -> Curve25519PublicKey` via [`HasPublicKey`].
pub trait SetupState<W>: HasPublicKey {
    /// The role-specific stage type.
    type Stage: fmt::Display + Copy + PartialEq;

    /// Returns true if the setup is complete and the wallet is ready for use.
    fn is_ready(&self) -> bool;

    /// Returns the current stage.
    fn stage(&self) -> Self::Stage;

    /// Returns true if the setup has been aborted.
    fn has_aborted(&self) -> bool;

    /// Returns the reason for aborting, if the setup was aborted.
    fn abort_reason(&self) -> Option<&MultisigSetupError>;

    /// Aborts the setup with the given reason.
    fn abort(&mut self, reason: MultisigSetupError);

    /// Returns a reference to the underlying wallet.
    fn wallet(&self) -> &W;

    /// Consumes the setup and returns the wallet if complete.
    fn finalize(self) -> Result<W, (Self, MultisigSetupError)> where Self: Sized;
}

// ============================================================================
// Merchant Setup
// ============================================================================

/// Merchant-side multisig wallet setup state machine.
///
/// The merchant protocol flow:
/// 1. `send_commitment()` - Generate and send commitment to customer
/// 2. `receive_peer_key()` - Receive customer's public key
/// 3. `send_public_key()` + `complete()` - Send our key and mark complete
#[derive(Debug)]
pub struct MerchantSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    stage: MerchantStage,
    wallet: W,
    abort_reason: Option<MultisigSetupError>,
}

impl<W> MerchantSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    /// Creates a new merchant setup. Returns an error if the wallet is not a merchant.
    pub fn new(wallet: W) -> Result<Self, MultisigSetupError> {
        if wallet.role() != ChannelRole::Merchant {
            return Err(MultisigSetupError::WrongRole);
        }
        Ok(Self { stage: MerchantStage::Initialized, wallet, abort_reason: None })
    }

    /// Generates and serializes a commitment to our public key.
    /// Transitions: `Initialized -> CommitmentSent`
    pub fn send_commitment(&mut self) -> Result<Vec<u8>, MultisigSetupError> {
        self.require_stage(MerchantStage::Initialized, "send_commitment")?;
        let data = self.wallet.commit_to_public_key().serialize();
        self.stage = MerchantStage::CommitmentSent;
        Ok(data)
    }

    /// Receives and stores the customer's public key.
    /// Transitions: `CommitmentSent -> AwaitingPeerKey`
    pub fn receive_peer_key(&mut self, data: &[u8]) -> Result<(), MultisigSetupError> {
        self.require_stage(MerchantStage::CommitmentSent, "receive_peer_key")?;
        let shared_key =
            SharedPublicKey::read(&mut &data[..]).map_err(|e| MultisigSetupError::DeserializationError(e.to_string()))?;
        self.wallet.set_peer_public_key(shared_key);
        self.stage = MerchantStage::AwaitingPeerKey;
        Ok(())
    }

    /// Serializes our public key for sending to the customer.
    /// Available in: `CommitmentSent`, `AwaitingPeerKey`
    pub fn send_public_key(&self) -> Result<Vec<u8>, MultisigSetupError> {
        match self.stage {
            MerchantStage::CommitmentSent | MerchantStage::AwaitingPeerKey => Ok(self.wallet.shared_public_key().serialize()),
            _ => Err(self.invalid_transition("send_public_key")),
        }
    }

    /// Marks the setup as complete after sending our public key.
    /// Transitions: `AwaitingPeerKey -> Complete`
    pub fn complete(&mut self) -> Result<(), MultisigSetupError> {
        self.require_stage(MerchantStage::AwaitingPeerKey, "complete")?;
        self.stage = MerchantStage::Complete;
        Ok(())
    }

    fn require_stage(&self, expected: MerchantStage, action: &'static str) -> Result<(), MultisigSetupError> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(self.invalid_transition(action))
        }
    }

    fn invalid_transition(&self, action: &'static str) -> MultisigSetupError {
        MultisigSetupError::InvalidStateTransition { state: self.stage.to_string(), action }
    }
}

impl<W> SetupState<W> for MerchantSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    type Stage = MerchantStage;

    fn is_ready(&self) -> bool {
        self.stage == MerchantStage::Complete
    }

    fn stage(&self) -> MerchantStage {
        self.stage
    }

    fn has_aborted(&self) -> bool {
        self.stage == MerchantStage::Aborted
    }

    fn abort_reason(&self) -> Option<&MultisigSetupError> {
        self.abort_reason.as_ref()
    }

    fn abort(&mut self, reason: MultisigSetupError) {
        self.stage = MerchantStage::Aborted;
        self.abort_reason = Some(reason);
    }

    fn wallet(&self) -> &W {
        &self.wallet
    }

    #[allow(clippy::result_large_err)]
    fn finalize(self) -> Result<W, (Self, MultisigSetupError)> {
        if self.stage == MerchantStage::Complete {
            Ok(self.wallet)
        } else {
            let error = MultisigSetupError::InvalidStateTransition { state: self.stage.to_string(), action: "finalize" };
            Err((self, error))
        }
    }
}

impl<W> HasRole for MerchantSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    fn role(&self) -> ChannelRole {
        ChannelRole::Merchant
    }
}

impl<W> HasPublicKey for MerchantSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    fn public_key(&self) -> Curve25519PublicKey {
        self.wallet.public_key()
    }
}

// ============================================================================
// Customer Setup
// ============================================================================

/// Customer-side multisig wallet setup state machine.
///
/// The customer protocol flow:
/// 1. `receive_commitment()` - Receive and store merchant's commitment
/// 2. `send_public_key()` - Send our public key to merchant
/// 3. `receive_peer_key()` - Receive merchant's public key
/// 4. `verify()` - Verify merchant's key matches commitment
#[derive(Debug)]
pub struct CustomerSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    stage: CustomerStage,
    wallet: W,
    abort_reason: Option<MultisigSetupError>,
}

impl<W> CustomerSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    /// Creates a new customer setup. Returns an error if the wallet is not a customer.
    pub fn new(wallet: W) -> Result<Self, MultisigSetupError> {
        if wallet.role() != ChannelRole::Customer {
            return Err(MultisigSetupError::WrongRole);
        }
        Ok(Self { stage: CustomerStage::AwaitingPeerCommitment, wallet, abort_reason: None })
    }

    /// Receives and stores the merchant's commitment.
    /// Transitions: `AwaitingPeerCommitment -> AwaitingPeerKey`
    pub fn receive_commitment(&mut self, data: &[u8]) -> Result<(), MultisigSetupError> {
        self.require_stage(CustomerStage::AwaitingPeerCommitment, "receive_commitment")?;
        let commitment = PublicKeyCommitment::read(&mut &data[..])
            .map_err(|e| MultisigSetupError::DeserializationError(e.to_string()))?;
        self.wallet.set_peer_public_key_commitment(commitment);
        self.stage = CustomerStage::AwaitingPeerKey;
        Ok(())
    }

    /// Serializes our public key for sending to the merchant.
    /// Available in: `AwaitingPeerKey`
    pub fn send_public_key(&self) -> Result<Vec<u8>, MultisigSetupError> {
        self.require_stage(CustomerStage::AwaitingPeerKey, "send_public_key")?;
        Ok(self.wallet.shared_public_key().serialize())
    }

    /// Receives and stores the merchant's public key.
    /// Transitions: `AwaitingPeerKey -> AwaitingVerification`
    pub fn receive_peer_key(&mut self, data: &[u8]) -> Result<(), MultisigSetupError> {
        self.require_stage(CustomerStage::AwaitingPeerKey, "receive_peer_key")?;
        let shared_key =
            SharedPublicKey::read(&mut &data[..]).map_err(|e| MultisigSetupError::DeserializationError(e.to_string()))?;
        self.wallet.set_peer_public_key(shared_key);
        self.stage = CustomerStage::AwaitingVerification;
        Ok(())
    }

    /// Verifies that the merchant's public key matches their commitment.
    /// Transitions: `AwaitingVerification -> Complete`
    pub fn verify(&mut self) -> Result<(), MultisigSetupError> {
        self.require_stage(CustomerStage::AwaitingVerification, "verify")?;
        self.wallet.verify_peer_public_key()?;
        self.stage = CustomerStage::Complete;
        Ok(())
    }

    fn require_stage(&self, expected: CustomerStage, action: &'static str) -> Result<(), MultisigSetupError> {
        if self.stage == expected {
            Ok(())
        } else {
            Err(self.invalid_transition(action))
        }
    }

    fn invalid_transition(&self, action: &'static str) -> MultisigSetupError {
        MultisigSetupError::InvalidStateTransition { state: self.stage.to_string(), action }
    }
}

impl<W> SetupState<W> for CustomerSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    type Stage = CustomerStage;

    fn is_ready(&self) -> bool {
        self.stage == CustomerStage::Complete
    }

    fn stage(&self) -> CustomerStage {
        self.stage
    }

    fn has_aborted(&self) -> bool {
        self.stage == CustomerStage::Aborted
    }

    fn abort_reason(&self) -> Option<&MultisigSetupError> {
        self.abort_reason.as_ref()
    }

    fn abort(&mut self, reason: MultisigSetupError) {
        self.stage = CustomerStage::Aborted;
        self.abort_reason = Some(reason);
    }

    fn wallet(&self) -> &W {
        &self.wallet
    }

    #[allow(clippy::result_large_err)]
    fn finalize(self) -> Result<W, (Self, MultisigSetupError)> {
        if self.stage == CustomerStage::Complete {
            Ok(self.wallet)
        } else {
            let error = MultisigSetupError::InvalidStateTransition { state: self.stage.to_string(), action: "finalize" };
            Err((self, error))
        }
    }
}

impl<W> HasRole for CustomerSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    fn role(&self) -> ChannelRole {
        ChannelRole::Customer
    }
}

impl<W> HasPublicKey for CustomerSetup<W>
where
    W: LinkedMultisigWallets<Blake2b512, SharedKeyType = SharedPublicKey>,
{
    fn public_key(&self) -> Curve25519PublicKey {
        self.wallet.public_key()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impls::multisig::MultisigWalletKeyRing;
    use rand_core::OsRng;

    #[test]
    fn merchant_happy_path() {
        let mut rng = OsRng;
        let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
        let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

        let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
        let mut customer = CustomerSetup::new(customer_keyring).unwrap();

        // Merchant sends commitment
        assert_eq!(merchant.stage(), MerchantStage::Initialized);
        let commitment = merchant.send_commitment().unwrap();
        assert_eq!(merchant.stage(), MerchantStage::CommitmentSent);

        // Customer receives commitment and sends key
        customer.receive_commitment(&commitment).unwrap();
        let customer_key = customer.send_public_key().unwrap();

        // Merchant receives key and sends their key
        merchant.receive_peer_key(&customer_key).unwrap();
        assert_eq!(merchant.stage(), MerchantStage::AwaitingPeerKey);

        let merchant_key = merchant.send_public_key().unwrap();
        merchant.complete().unwrap();
        assert!(merchant.is_ready());

        // Customer receives key and verifies
        customer.receive_peer_key(&merchant_key).unwrap();
        customer.verify().unwrap();
        assert!(customer.is_ready());

        // Finalize both
        let m_wallet = merchant.finalize().unwrap();
        let c_wallet = customer.finalize().unwrap();
        assert_eq!(m_wallet.sorted_public_keys().unwrap(), c_wallet.sorted_public_keys().unwrap());
    }

    #[test]
    fn merchant_invalid_transitions() {
        let mut rng = OsRng;
        let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
        let mut merchant = MerchantSetup::new(keyring).unwrap();

        // Can't receive key before sending commitment
        let fake_data = vec![0u8; 64];
        assert!(merchant.receive_peer_key(&fake_data).is_err());

        // Can't complete before receiving peer key
        assert!(merchant.complete().is_err());
    }

    #[test]
    fn customer_invalid_transitions() {
        let mut rng = OsRng;
        let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);
        let mut customer = CustomerSetup::new(keyring).unwrap();

        // Can't send key before receiving commitment
        assert!(customer.send_public_key().is_err());

        // Can't verify before receiving peer key
        assert!(customer.verify().is_err());
    }

    #[test]
    fn abort_preserves_reason() {
        let mut rng = OsRng;
        let keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
        let mut merchant = MerchantSetup::new(keyring).unwrap();

        merchant.abort(MultisigSetupError::Timeout);
        assert!(merchant.has_aborted());
        assert!(matches!(merchant.abort_reason(), Some(MultisigSetupError::Timeout)));
    }

    #[test]
    fn commitment_mismatch_detected() {
        let mut rng = OsRng;
        let merchant_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
        let customer_keyring = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

        let mut merchant = MerchantSetup::new(merchant_keyring).unwrap();
        let mut customer = CustomerSetup::new(customer_keyring).unwrap();

        // Bad commitment
        customer.receive_commitment(&[42u8; 32]).unwrap();
        let customer_key = customer.send_public_key().unwrap();

        merchant.send_commitment().unwrap();
        merchant.receive_peer_key(&customer_key).unwrap();
        let merchant_key = merchant.send_public_key().unwrap();

        customer.receive_peer_key(&merchant_key).unwrap();
        assert!(matches!(customer.verify(), Err(MultisigSetupError::CommitmentMismatch)));
    }

    #[test]
    fn stage_display() {
        assert_eq!(MerchantStage::Initialized.to_string(), "Initialized");
        assert_eq!(MerchantStage::Complete.to_string(), "Complete");
        assert_eq!(CustomerStage::AwaitingPeerCommitment.to_string(), "AwaitingPeerCommitment");
        assert_eq!(CustomerStage::Complete.to_string(), "Complete");
    }
}
