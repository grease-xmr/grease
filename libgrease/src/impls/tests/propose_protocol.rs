//! Tests for the ProposeProtocol traits.
//!
//! These tests verify the channel proposal flow between merchant (proposer) and customer (proposee).

use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelIdMetadata;
use crate::cryptography::keys::{Curve25519PublicKey, PublicKey};
use crate::grease_protocol::propose_channel::{
    ChannelSeedConfig, ProposeProtocolCommon, ProposeProtocolError, ProposeProtocolProposee, ProposeProtocolProposer,
};
use crate::monero::data_objects::ClosingAddresses;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::{ChannelSeedBuilder, ChannelSeedInfo, NewChannelProposal, RejectNewChannelReason};
use monero::{Address, Network};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::str::FromStr;

const ALICE_ADDRESS: &str =
    "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
const BOB_ADDRESS: &str =
    "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

/// Test implementation of ProposeProtocolProposer (merchant side)
struct MerchantProposer {
    role: ChannelRole,
    channel_key: Curve25519PublicKey,
    seed_info: Option<ChannelSeedInfo>,
    channel_id: Option<ChannelIdMetadata>,
    received_proposal: Option<NewChannelProposal>,
    nonce: u64,
}

impl MerchantProposer {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (_, channel_key) = Curve25519PublicKey::keypair(rng);
        Self {
            role: ChannelRole::Merchant,
            channel_key,
            seed_info: None,
            channel_id: None,
            received_proposal: None,
            nonce: rng.next_u64(),
        }
    }
}

impl HasRole for MerchantProposer {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl ProposeProtocolCommon for MerchantProposer {
    fn channel_id(&self) -> Option<&ChannelIdMetadata> {
        self.channel_id.as_ref()
    }

    fn seed_info(&self) -> Option<&ChannelSeedInfo> {
        self.seed_info.as_ref()
    }

    fn validate_seed_info(&self) -> Result<(), ProposeProtocolError> {
        let seed =
            self.seed_info.as_ref().ok_or_else(|| ProposeProtocolError::MissingInformation("seed info".into()))?;
        if seed.initial_balances.total().is_zero() {
            return Err(ProposeProtocolError::BalanceValidationFailed("total balance is zero".into()));
        }
        Ok(())
    }
}

impl ProposeProtocolProposer for MerchantProposer {
    fn create_channel_seed<R: RngCore + CryptoRng>(
        &mut self,
        _rng: &mut R,
        config: ChannelSeedConfig,
    ) -> Result<ChannelSeedInfo, ProposeProtocolError> {
        let initial_balances =
            Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("1.0").unwrap());

        let seed = ChannelSeedBuilder::new(ChannelRole::Customer, Network::Stagenet)
            .with_kes_public_key(config.kes_public_key)
            .with_initial_balances(initial_balances)
            .with_closing_address(config.closing_address)
            .with_channel_key(self.channel_key.clone())
            .with_channel_nonce(self.nonce)
            .build()
            .map_err(|e| ProposeProtocolError::MissingInformation(e.to_string()))?;

        self.seed_info = Some(seed.clone());
        Ok(seed)
    }

    fn receive_proposal(&mut self, proposal: &NewChannelProposal) -> Result<(), ProposeProtocolError> {
        if self.received_proposal.is_some() {
            return Err(ProposeProtocolError::ProposalAlreadyReceived);
        }

        // Validate the proposal matches our seed info
        let seed = self.seed_info.as_ref().ok_or(ProposeProtocolError::MissingInformation("seed info".into()))?;

        if proposal.seed.kes_public_key != seed.kes_public_key {
            return Err(ProposeProtocolError::InvalidProposal("KES public key mismatch".into()));
        }

        if proposal.seed.initial_balances != seed.initial_balances {
            return Err(ProposeProtocolError::InvalidProposal("balance mismatch".into()));
        }

        // Store the channel ID from the proposal
        self.channel_id = Some(proposal.channel_id.clone());
        self.received_proposal = Some(proposal.clone());
        Ok(())
    }

    fn accept_proposal(&self) -> Result<NewChannelProposal, ProposeProtocolError> {
        self.received_proposal.clone().ok_or(ProposeProtocolError::NoProposalReceived)
    }

    fn reject_proposal(&self, _reason: RejectNewChannelReason) -> Result<(), ProposeProtocolError> {
        if self.received_proposal.is_none() {
            return Err(ProposeProtocolError::NoProposalReceived);
        }
        Ok(())
    }
}

/// Test implementation of ProposeProtocolProposee (customer side)
struct CustomerProposee {
    role: ChannelRole,
    channel_key: Curve25519PublicKey,
    seed_info: Option<ChannelSeedInfo>,
    channel_id: Option<ChannelIdMetadata>,
    sent_proposal: Option<NewChannelProposal>,
    nonce: u64,
    rejected: bool,
}

impl CustomerProposee {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let (_, channel_key) = Curve25519PublicKey::keypair(rng);
        Self {
            role: ChannelRole::Customer,
            channel_key,
            seed_info: None,
            channel_id: None,
            sent_proposal: None,
            nonce: rng.next_u64(),
            rejected: false,
        }
    }
}

impl HasRole for CustomerProposee {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl ProposeProtocolCommon for CustomerProposee {
    fn channel_id(&self) -> Option<&ChannelIdMetadata> {
        self.channel_id.as_ref()
    }

    fn seed_info(&self) -> Option<&ChannelSeedInfo> {
        self.seed_info.as_ref()
    }

    fn validate_seed_info(&self) -> Result<(), ProposeProtocolError> {
        let seed = self.seed_info.as_ref().ok_or_else(|| ProposeProtocolError::SeedInfoNotReceived)?;
        if seed.initial_balances.total().is_zero() {
            return Err(ProposeProtocolError::BalanceValidationFailed("total balance is zero".into()));
        }
        Ok(())
    }
}

impl ProposeProtocolProposee for CustomerProposee {
    fn receive_seed_info(&mut self, seed: ChannelSeedInfo) -> Result<(), ProposeProtocolError> {
        if seed.initial_balances.total().is_zero() {
            return Err(ProposeProtocolError::InvalidSeedInfo("zero total balance".into()));
        }
        self.seed_info = Some(seed);
        Ok(())
    }

    fn create_proposal<R: RngCore + CryptoRng>(
        &self,
        _rng: &mut R,
        closing_address: &Address,
    ) -> Result<NewChannelProposal, ProposeProtocolError> {
        let seed = self.seed_info.as_ref().ok_or(ProposeProtocolError::SeedInfoNotReceived)?;

        let closing_addresses =
            ClosingAddresses::new(&closing_address.to_string(), &seed.merchant_closing_address.to_string())
                .map_err(|e| ProposeProtocolError::InvalidProposal(e.to_string()))?;

        let channel_id = ChannelIdMetadata::new(
            seed.merchant_channel_key.clone(),
            self.channel_key.clone(),
            seed.initial_balances,
            closing_addresses,
            seed.merchant_nonce,
            self.nonce,
        );

        Ok(NewChannelProposal { network: seed.network, channel_id, seed: seed.clone() })
    }

    fn handle_acceptance(&mut self, accepted: &NewChannelProposal) -> Result<(), ProposeProtocolError> {
        // Verify the accepted proposal matches what we sent
        if let Some(ref sent) = self.sent_proposal {
            if sent.channel_id.name() != accepted.channel_id.name() {
                return Err(ProposeProtocolError::ChannelIdMismatch {
                    expected: sent.channel_id.name().to_string(),
                    actual: accepted.channel_id.name().to_string(),
                });
            }
        }
        self.channel_id = Some(accepted.channel_id.clone());
        Ok(())
    }

    fn handle_rejection(&mut self, _reason: RejectNewChannelReason) -> Result<(), ProposeProtocolError> {
        self.rejected = true;
        Ok(())
    }
}

#[test]
fn test_merchant_create_seed_info() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);

    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };

    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");

    assert_eq!(seed.kes_public_key, "test_kes_pubkey");
    assert_eq!(seed.role, ChannelRole::Customer);
    assert!(merchant.seed_info().is_some());
    assert!(merchant.validate_seed_info().is_ok());
}

#[test]
fn test_customer_receive_seed_and_propose() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);
    let mut customer = CustomerProposee::new(&mut rng);

    // Merchant creates seed
    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };
    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");

    // Customer receives seed
    customer.receive_seed_info(seed).expect("should receive seed");
    assert!(customer.seed_info().is_some());
    assert!(customer.validate_seed_info().is_ok());

    // Customer creates proposal
    let customer_address = Address::from_str(ALICE_ADDRESS).unwrap();
    let proposal = customer.create_proposal(&mut rng, &customer_address).expect("should create proposal");

    assert_eq!(proposal.network, Network::Stagenet);
    assert!(proposal.channel_id.name().as_str().starts_with("XGC"));
}

#[test]
fn test_full_proposal_flow() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);
    let mut customer = CustomerProposee::new(&mut rng);

    // 1. Merchant creates seed info
    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };
    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");

    // 2. Customer receives seed info
    customer.receive_seed_info(seed).expect("should receive seed");

    // 3. Customer creates proposal
    let customer_address = Address::from_str(ALICE_ADDRESS).unwrap();
    let proposal = customer.create_proposal(&mut rng, &customer_address).expect("should create proposal");
    customer.sent_proposal = Some(proposal.clone());

    // 4. Merchant receives proposal
    merchant.receive_proposal(&proposal).expect("should receive proposal");

    // 5. Merchant accepts proposal
    let accepted = merchant.accept_proposal().expect("should accept proposal");

    // 6. Customer handles acceptance
    customer.handle_acceptance(&accepted).expect("should handle acceptance");

    // Verify both have the same channel ID
    assert_eq!(merchant.channel_id().unwrap().name(), customer.channel_id().unwrap().name());
}

#[test]
fn test_proposal_rejection() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);
    let mut customer = CustomerProposee::new(&mut rng);

    // Setup
    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };
    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");
    customer.receive_seed_info(seed).expect("should receive seed");

    let customer_address = Address::from_str(ALICE_ADDRESS).unwrap();
    let proposal = customer.create_proposal(&mut rng, &customer_address).expect("should create proposal");

    // Merchant receives and rejects
    merchant.receive_proposal(&proposal).expect("should receive proposal");
    let reason = RejectNewChannelReason::new("insufficient funds");
    merchant.reject_proposal(reason.clone()).expect("should reject proposal");

    // Customer handles rejection
    customer.handle_rejection(reason).expect("should handle rejection");
    assert!(customer.rejected);
}

#[test]
fn test_duplicate_proposal_rejected() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);
    let customer = CustomerProposee::new(&mut rng);

    // Setup
    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };
    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");

    // Create a minimal valid proposal
    let closing_addresses = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).unwrap();
    let channel_id = ChannelIdMetadata::new(
        merchant.channel_key.clone(),
        customer.channel_key.clone(),
        seed.initial_balances,
        closing_addresses,
        seed.merchant_nonce,
        12345,
    );
    let proposal = NewChannelProposal { network: seed.network, channel_id, seed: seed.clone() };

    // First proposal succeeds
    merchant.receive_proposal(&proposal).expect("first proposal should succeed");

    // Second proposal fails
    let result = merchant.receive_proposal(&proposal);
    assert!(matches!(result, Err(ProposeProtocolError::ProposalAlreadyReceived)));
}

#[test]
fn test_accept_without_proposal_fails() {
    let mut rng = OsRng;
    let merchant = MerchantProposer::new(&mut rng);

    let result = merchant.accept_proposal();
    assert!(matches!(result, Err(ProposeProtocolError::NoProposalReceived)));
}

#[test]
fn test_create_proposal_without_seed_fails() {
    let mut rng = OsRng;
    let customer = CustomerProposee::new(&mut rng);

    let customer_address = Address::from_str(ALICE_ADDRESS).unwrap();
    let result = customer.create_proposal(&mut rng, &customer_address);
    assert!(matches!(result, Err(ProposeProtocolError::SeedInfoNotReceived)));
}

#[test]
fn test_invalid_seed_info_rejected() {
    let mut rng = OsRng;
    let mut customer = CustomerProposee::new(&mut rng);

    // Create seed with zero balance
    let seed = ChannelSeedBuilder::new(ChannelRole::Customer, Network::Stagenet)
        .with_kes_public_key("test_kes")
        .with_initial_balances(Balances::new(
            MoneroAmount::from_xmr("0.0").unwrap(),
            MoneroAmount::from_xmr("0.0").unwrap(),
        ))
        .with_closing_address(Address::from_str(BOB_ADDRESS).unwrap())
        .with_channel_key(customer.channel_key.clone())
        .with_channel_nonce(12345)
        .build()
        .unwrap();

    let result = customer.receive_seed_info(seed);
    assert!(matches!(result, Err(ProposeProtocolError::InvalidSeedInfo(_))));
}

#[test]
fn test_channel_id_calculation() {
    let mut rng = OsRng;
    let mut merchant = MerchantProposer::new(&mut rng);
    let mut customer = CustomerProposee::new(&mut rng);

    let config = ChannelSeedConfig {
        kes_public_key: "test_kes_pubkey".to_string(),
        closing_address: Address::from_str(BOB_ADDRESS).unwrap(),
    };
    let seed = merchant.create_channel_seed(&mut rng, config).expect("should create seed");
    customer.receive_seed_info(seed).expect("should receive seed");

    let customer_address = Address::from_str(ALICE_ADDRESS).unwrap();
    let proposal = customer.create_proposal(&mut rng, &customer_address).expect("should create proposal");

    // Channel ID should be deterministic and start with XGC prefix
    let channel_id = proposal.channel_id.name();
    assert!(channel_id.as_str().starts_with("XGC"));
    assert_eq!(channel_id.as_str().len(), 65);
}
