//! Tests for the channel proposal FSM.

use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::ChannelId;
use crate::cryptography::keys::Curve25519Secret;
use crate::grease_protocol::propose_channel::MerchantSeedBuilder;
use crate::grease_protocol::MerchantSeedInfo;
use crate::key_escrow_services::{KesConfiguration, KesImplementation};
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
use crate::state_machine::{
    AwaitProposal, ChannelClosedReason, ChannelProposer, EstablishingState, ProposalConfirmed, ProposalResponse,
    RejectProposalReason, TimeoutReason,
};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::ff::Field;
use ciphersuite::group::Group;
use monero::Network;
use rand_core::OsRng;
use std::str::FromStr;
use zeroize::Zeroizing;

const MERCHANT_ADDRESS: &str =
    "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
const CUSTOMER_ADDRESS: &str =
    "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

fn test_balances() -> Balances {
    Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("1.25").unwrap())
}

fn zero_balances() -> Balances {
    Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.0").unwrap())
}

fn build_merchant_seed_with_balances(
    kes_private_key: &XmrScalar,
    balances: Balances,
) -> (MerchantSeedInfo, Zeroizing<XmrScalar>) {
    let channel_secret = Zeroizing::new(XmrScalar::random(&mut rand_core::OsRng));
    let kes_pk = XmrPoint::generator() * kes_private_key;
    let peer_pk = XmrPoint::generator() * *channel_secret;
    let kes_config = KesConfiguration::new_with_defaults(kes_pk, peer_pk);
    let merchant_secret = XmrScalar::random(&mut rand_core::OsRng);
    let seed = MerchantSeedBuilder::new(Network::Mainnet, KesImplementation::StandaloneEd25519)
        .with_kes_config(kes_config)
        .with_initial_balances(balances)
        .derive_channel_pubkey(&merchant_secret)
        .with_channel_nonce(100)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap())
        .build()
        .expect("to build merchant seed info");
    (seed, channel_secret)
}

fn build_merchant_seed(kes_private_key: &XmrScalar) -> (MerchantSeedInfo, Zeroizing<XmrScalar>) {
    build_merchant_seed_with_balances(kes_private_key, test_balances())
}

/// C1: Customer receives seed info, creates ChannelProposer, and generates a proposal.
fn customer_creates_proposal(seed: MerchantSeedInfo) -> ChannelProposer {
    let customer_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let customer_addr = CUSTOMER_ADDRESS.parse().unwrap();
    let proposer = ChannelProposer::new(seed, customer_secret, partial_spend_key, customer_addr, 200)
        .expect("should create proposer");
    assert_eq!(proposer.role(), ChannelRole::Customer);
    proposer
}

/// Returns a ChannelId that won't match any legitimately derived channel ID.
fn fake_channel_id() -> ChannelId {
    ChannelId::from_str("XGC00000000000000000000000000000000000000000000000000000000000000").unwrap()
}

/// Creates a new set of EstablishingState for the merchant and customer by simulating a successful proposal exchange.
///
/// Private keys are random. The initial channel balance is fixed at 1.25-0 for customer-merchant.
pub fn propose_channel() -> (EstablishingState, EstablishingState, XmrScalar) {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let merchant_partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, merchant_partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (customer, proposal) = customer.into_proposal();
    let (merchant, response) = merchant.receive_proposal(proposal).expect("Merchant should accept valid proposal");

    let (customer, confirmation) =
        customer.handle_response(response).expect("Customer should accept merchant acceptance");
    let merchant = merchant.handle_confirmation(confirmation).expect("Merchant should accept valid proposal");
    (merchant, customer, kes_private_key)
}

#[test]
fn happy_path() {
    let (merchant, customer, _) = propose_channel();
    assert_eq!(merchant.stage(), LifecycleStage::Establishing);
    assert_eq!(customer.stage(), LifecycleStage::Establishing);
}

// ====================== M2: ReceiveProposal::receive_proposal ======================

/// M2: Merchant rejects a proposal with tampered seed info.
#[test]
fn merchant_rejects_tampered_seed() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    // Tamper with the echoed seed's merchant nonce
    proposal.seed.merchant_nonce = 999;
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::SeedMismatch));
}

/// M2: Merchant rejects a proposal with zero total balance.
#[test]
fn merchant_rejects_zero_balance() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed_with_balances(&kes_private_key, zero_balances());
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, proposal) = customer.into_proposal();
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::ZeroTotalValue));
}

// ====================== C2: AwaitingProposalResponse::handle_response ======================

/// C2: Customer handles merchant rejection, transitions to Closed.
#[test]
fn customer_handles_rejection() {
    let kes_private_key = XmrScalar::random(&mut rand_core::OsRng);
    let (seed, _merchant_secret) = build_merchant_seed(&kes_private_key);
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Rejected(RejectProposalReason::new("Not interested"));
    let closed = customer.handle_response(response).unwrap_err();
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

/// C2: Customer rejects acceptance with tampered customer_channel_key.
///
/// If the merchant returns an acceptance with a channel ID that doesn't match the one the
/// customer computed (e.g. because the merchant used a different key), the customer closes.
#[test]
fn customer_rejects_tampered_key_in_acceptance() {
    let kes_private_key = XmrScalar::random(&mut rand_core::OsRng);
    let (seed, _merchant_secret) = build_merchant_seed(&kes_private_key);
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Accepted(fake_channel_id());
    let closed = customer.handle_response(response).unwrap_err();
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

/// C2: AwaitingProposalResponse can timeout to Closed.
#[test]
fn awaiting_response_timeout() {
    let kes_private_key = XmrScalar::random(&mut rand_core::OsRng);
    let (seed, _merchant_secret) = build_merchant_seed(&kes_private_key);
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let reason = TimeoutReason::new("No response from merchant", LifecycleStage::Establishing);
    let closed = customer.timeout(reason);
    assert!(matches!(closed.reason(), ChannelClosedReason::Timeout(_)));
    assert_eq!(closed.final_balances(), test_balances());
}

// ====================== M3: AwaitingConfirmation ======================

/// M3: Merchant rejects confirmation with mismatched channel ID.
#[test]
fn merchant_rejects_mismatched_confirmation() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, proposal) = customer.into_proposal();
    let (merchant, _response) = merchant.receive_proposal(proposal).expect("Merchant should accept valid proposal");
    let bad_confirmation = ProposalConfirmed { channel_id: fake_channel_id() };
    let closed = merchant.handle_confirmation(bad_confirmation).unwrap_err();
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

/// AwaitingConfirmation can timeout to Closed.
#[test]
fn awaiting_confirmation_timeout() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, proposal) = customer.into_proposal();
    let (merchant, _response) = merchant.receive_proposal(proposal).expect("Merchant should accept valid proposal");
    let reason = TimeoutReason::new("Customer did not confirm", LifecycleStage::Establishing);
    let closed = merchant.timeout(reason);
    assert!(matches!(closed.reason(), ChannelClosedReason::Timeout(_)));
    assert_eq!(closed.final_balances(), test_balances());
}

/// AwaitingConfirmation can reject to Closed.
#[test]
fn awaiting_confirmation_reject() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, proposal) = customer.into_proposal();
    let (merchant, _response) = merchant.receive_proposal(proposal).expect("Merchant should accept valid proposal");
    let reason = RejectProposalReason::new("Customer data is suspicious");
    let closed = merchant.reject(reason);
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

// ====================== Additional edge cases ======================

/// Both parties compute the same channel ID after a successful proposal exchange.
#[test]
fn established_channel_ids_match() {
    let (merchant, customer, _) = propose_channel();
    assert_eq!(merchant.metadata.channel_id().name(), customer.metadata.channel_id().name());
}

/// Merchant and customer have the correct roles after establishing.
#[test]
fn established_roles_are_correct() {
    let (merchant, customer, _) = propose_channel();
    assert_eq!(merchant.metadata.role(), ChannelRole::Merchant);
    assert_eq!(customer.metadata.role(), ChannelRole::Customer);
}

/// Closing during the proposal phase preserves the initial balances as final balances.
#[test]
fn rejection_preserves_initial_balances() {
    let kes_private_key = XmrScalar::random(&mut rand_core::OsRng);
    let (seed, _merchant_secret) = build_merchant_seed(&kes_private_key);
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Rejected(RejectProposalReason::new("Declined"));
    let closed = customer.handle_response(response).unwrap_err();
    assert_eq!(closed.final_balances(), test_balances());
}

/// Tampered seed with a modified closing address is also detected.
#[test]
fn merchant_rejects_tampered_closing_address() {
    let kes_private_key = XmrScalar::random(&mut OsRng);
    let (seed, merchant_secret) = build_merchant_seed(&kes_private_key);
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    // Tamper with the closing address in the echoed seed
    proposal.seed.merchant_closing_address = CUSTOMER_ADDRESS.parse().unwrap();
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::SeedMismatch));
}
