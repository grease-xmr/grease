use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey, PublicKeyCommitment};
use crate::grease_protocol::multisig_wallet::{
    HasPublicKey, HasSecretKey, LinkedMultisigWallets, MultisigWalletError, SharedPublicKey,
};
use crate::payment_channel::{ChannelRole, HasRole};
use blake2::Blake2b512;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// A mock implementation of [`LinkedMultisigWallets`] for testing the multisig wallet setup protocol.
///
/// This mock provides deterministic key generation from a seed and the ability to inject failures
/// for testing error handling paths.
#[derive(Debug, Clone)]
pub struct MockMultisigWallet {
    role: ChannelRole,
    partial_spend_key: Curve25519Secret,
    public_key: Curve25519PublicKey,
    peer_commitment: Option<PublicKeyCommitment>,
    peer_public_key: Option<SharedPublicKey>,
    fail_on_verify: bool,
    fail_on_receive: bool,
}

impl MockMultisigWallet {
    /// Creates a new mock wallet with deterministic keys derived from the seed.
    ///
    /// The seed ensures reproducible test results while still using cryptographically
    /// valid key generation.
    pub fn new_deterministic(role: ChannelRole, seed: [u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (partial_spend_key, public_key) = Curve25519PublicKey::keypair(&mut rng);
        Self {
            role,
            partial_spend_key,
            public_key,
            peer_commitment: None,
            peer_public_key: None,
            fail_on_verify: false,
            fail_on_receive: false,
        }
    }

    /// Configures the mock to fail on the next verification attempt.
    ///
    /// This is useful for testing error handling when commitment verification fails.
    pub fn inject_verify_failure(&mut self) {
        self.fail_on_verify = true;
    }

    /// Configures the mock to fail on the next receive attempt.
    ///
    /// This is useful for testing error handling when receiving peer data fails.
    pub fn inject_receive_failure(&mut self) {
        self.fail_on_receive = true;
    }

    /// Resets any injected failures.
    pub fn clear_injected_failures(&mut self) {
        self.fail_on_verify = false;
        self.fail_on_receive = false;
    }
}

impl HasRole for MockMultisigWallet {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl HasPublicKey for MockMultisigWallet {
    fn public_key(&self) -> Curve25519PublicKey {
        self.public_key
    }
}

impl HasSecretKey for MockMultisigWallet {
    fn secret_key(&self) -> Curve25519Secret {
        self.partial_spend_key.clone()
    }
}

impl LinkedMultisigWallets<Blake2b512> for MockMultisigWallet {
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
        if !self.fail_on_receive {
            self.peer_public_key = Some(public_key);
        }
    }

    fn peer_shared_public_key(&self) -> Result<&Self::SharedKeyType, MultisigWalletError> {
        self.peer_public_key.as_ref().ok_or(MultisigWalletError::MissingInformation("Peer public key".into()))
    }

    fn verify_peer_public_key(&self) -> Result<(), MultisigWalletError> {
        if self.fail_on_verify {
            return Err(MultisigWalletError::IncorrectPublicKey);
        }
        // Delegate to the default implementation which does the real verification
        let peer_pubkey = self.peer_shared_public_key()?;
        if self.role() == peer_pubkey.role() {
            return Err(MultisigWalletError::IncompatibleRoles);
        }
        let commitment = self.peer_public_key_commitment()?;
        use crate::cryptography::Commit;
        match peer_pubkey.verify(commitment) {
            true => Ok(()),
            false => Err(MultisigWalletError::IncorrectPublicKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_key_generation() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let wallet1a = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed1);
        let wallet1b = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed1);
        let wallet2 = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed2);

        // Same seed produces same keys
        assert_eq!(wallet1a.public_key(), wallet1b.public_key());

        // Different seeds produce different keys
        assert_ne!(wallet1a.public_key(), wallet2.public_key());
    }

    #[test]
    fn test_role_assignment() {
        let seed = [42u8; 32];

        let merchant = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed);
        let customer = MockMultisigWallet::new_deterministic(ChannelRole::Customer, seed);

        assert_eq!(merchant.role(), ChannelRole::Merchant);
        assert_eq!(customer.role(), ChannelRole::Customer);
    }

    #[test]
    fn test_inject_verify_failure() {
        let seed = [1u8; 32];
        let mut merchant = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed);
        let customer = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [2u8; 32]);

        // Set up the merchant with valid peer data
        merchant.set_peer_public_key_commitment(customer.commit_to_public_key());
        merchant.set_peer_public_key(customer.shared_public_key());

        // Inject failure
        merchant.inject_verify_failure();

        // Verification should fail
        let result = merchant.verify_peer_public_key();
        assert!(matches!(result, Err(MultisigWalletError::IncorrectPublicKey)));
    }

    #[test]
    fn test_clear_injected_failures() {
        let seed = [1u8; 32];
        let mut merchant = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, seed);
        let customer = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [2u8; 32]);

        // Set up valid peer data
        merchant.set_peer_public_key_commitment(customer.commit_to_public_key());
        merchant.set_peer_public_key(customer.shared_public_key());

        // Inject and then clear failure
        merchant.inject_verify_failure();
        merchant.clear_injected_failures();

        // Verification should succeed now
        let result = merchant.verify_peer_public_key();
        assert!(result.is_ok());
    }

    #[test]
    fn test_happy_path_with_mock() {
        let mut merchant = MockMultisigWallet::new_deterministic(ChannelRole::Merchant, [1u8; 32]);
        let mut customer = MockMultisigWallet::new_deterministic(ChannelRole::Customer, [2u8; 32]);

        // Merchant commits
        let commitment = merchant.commit_to_public_key();

        // Customer stores commitment
        customer.set_peer_public_key_commitment(commitment);

        // Exchange public keys
        let customer_key = customer.shared_public_key();
        let merchant_key = merchant.shared_public_key();

        merchant.set_peer_public_key(customer_key);
        customer.set_peer_public_key(merchant_key);

        // Customer verifies
        assert!(customer.verify_peer_public_key().is_ok());

        // Both should have matching sorted public keys
        let merchant_sorted = merchant.sorted_public_keys().unwrap();
        let customer_sorted = customer.sorted_public_keys().unwrap();
        assert_eq!(merchant_sorted, customer_sorted);
    }
}
