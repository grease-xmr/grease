//! Tests for the channel proposal FSM.

use crate::amount::MoneroAmount;
use crate::arbiter::ArbiterConfiguration;
use crate::balance::Balances;
use crate::channel_id::{ChannelId, ChannelIdMetadata};
use crate::cryptography::attestation::test_helpers::generate_master_keypair;
use crate::cryptography::keys::Curve25519Secret;
use crate::grease_protocol::propose_channel::{MerchantSeedBuilder, MissingSeedInfo};
use crate::grease_protocol::MerchantSeedInfo;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::InvalidProposal;
use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
use crate::state_machine::{
    AwaitProposal, ChannelClosedReason, ChannelProposer, EstablishingState, NewChannelProposal, ProposalConfirmed,
    ProposalResponse, ProposeProtocolError, RejectProposalReason, TimeoutReason,
};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::Group;
use monero::Network;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use std::str::FromStr;
use std::time::Duration;
use zeroize::Zeroizing;

const MERCHANT_ADDRESS: &str =
    "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
const CUSTOMER_ADDRESS: &str =
    "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

/// An arbiter configuration keyed by `seed`, so tests can build two that differ.
fn arbiter(seed: u64) -> ArbiterConfiguration {
    let (_, big_z) = generate_master_keypair(&mut ChaCha20Rng::seed_from_u64(seed));
    ArbiterConfiguration::new_with_defaults(big_z, format!("arbiter-{seed}"))
}

/// The arbiter every seed in these tests offers, and that the customer picks.
fn default_arbiter() -> ArbiterConfiguration {
    arbiter(1)
}

fn test_balances() -> Balances {
    Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("1.25").unwrap())
}

fn zero_balances() -> Balances {
    Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.0").unwrap())
}

/// A seed offering [`default_arbiter`], plus the merchant's channel secret matching its public key.
fn build_merchant_seed_with_balances(balances: Balances) -> (MerchantSeedInfo, Zeroizing<XmrScalar>) {
    let merchant_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let seed = MerchantSeedBuilder::new(Network::Mainnet)
        .with_arbiter(default_arbiter())
        .with_initial_balances(balances)
        .with_merchant_public_key(XmrPoint::generator() * *merchant_secret)
        .with_random_channel_nonce(&mut OsRng)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap())
        .build()
        .expect("to build merchant seed info");
    (seed, merchant_secret)
}

fn build_merchant_seed() -> (MerchantSeedInfo, Zeroizing<XmrScalar>) {
    build_merchant_seed_with_balances(test_balances())
}

/// C1: Customer receives seed info, creates ChannelProposer, and generates a proposal.
fn customer_creates_proposal(seed: MerchantSeedInfo) -> ChannelProposer {
    let customer_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let customer_addr = CUSTOMER_ADDRESS.parse().unwrap();
    let proposer = ChannelProposer::new(
        seed,
        default_arbiter(),
        customer_secret,
        partial_spend_key,
        customer_addr,
        OsRng.next_u64(),
    )
    .expect("should create proposer");
    assert_eq!(proposer.role(), ChannelRole::Customer);
    proposer
}

/// Returns a ChannelId that won't match any legitimately derived channel ID.
fn fake_channel_id() -> ChannelId {
    ChannelId::from_str("XGC00000000000000000000000000000000000000000000000000000000000000").unwrap()
}

/// Rebuild a proposal's channel-id metadata around a different arbiter, leaving every other field alone.
///
/// The arbiter is not part of the id transcript, so this keeps the channel id itself intact — exactly the case
/// the merchant's arbiter check has to catch.
fn swap_arbiter(proposal: &NewChannelProposal, arbiter: ArbiterConfiguration) -> ChannelIdMetadata {
    let id = &proposal.channel_id;
    ChannelIdMetadata::new(
        *id.merchant_key(),
        *id.customer_key(),
        id.initial_balance(),
        *id.closing_addresses(),
        arbiter,
        id.merchant_nonce(),
        id.customer_nonce(),
    )
}

/// Creates a new set of EstablishingState for the merchant and customer by simulating a successful proposal exchange.
///
/// Private keys are random. The initial channel balance is fixed at 1.25-0 for customer-merchant.
pub fn propose_channel() -> (EstablishingState, EstablishingState) {
    let (seed, merchant_secret) = build_merchant_seed();
    let merchant_partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, merchant_partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (customer, proposal) = customer.into_proposal();
    let (merchant, response) = merchant.receive_proposal(proposal).expect("Merchant should accept valid proposal");
    let (customer, confirmation) =
        customer.handle_response(response).expect("Customer should accept merchant acceptance");
    let merchant = merchant.handle_confirmation(confirmation).expect("Merchant should accept valid proposal");
    (merchant, customer)
}

#[test]
fn happy_path() {
    let (merchant, customer) = propose_channel();
    assert_eq!(merchant.stage(), LifecycleStage::Establishing);
    assert_eq!(customer.stage(), LifecycleStage::Establishing);
}

/// Both parties end up bound to the arbiter the customer picked out of the seed's offer.
#[test]
fn agreed_arbiter_reaches_both_parties() {
    let (merchant, customer) = propose_channel();
    assert_eq!(merchant.metadata.arbiter_configuration(), &default_arbiter());
    assert_eq!(customer.metadata.arbiter_configuration(), &default_arbiter());
    assert_eq!(customer.metadata.dispute_window(), default_arbiter().dispute_window());
}

// ====================== Seed construction ======================

/// Every required seed field is reported by name when it is left out.
#[test]
fn seed_builder_reports_missing_fields() {
    let complete = || {
        MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
            .with_arbiter(default_arbiter())
            .with_initial_balances(test_balances())
            .with_merchant_public_key(XmrPoint::generator())
            .with_random_channel_nonce(&mut OsRng)
            .with_closing_address(MERCHANT_ADDRESS.parse().unwrap())
    };
    assert!(complete().build().is_ok());

    let no_arbiter = MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
        .with_initial_balances(test_balances())
        .with_merchant_public_key(XmrPoint::generator())
        .with_random_channel_nonce(&mut OsRng)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap());
    assert!(matches!(no_arbiter.build(), Err(MissingSeedInfo::AcceptedArbiters)));

    let no_balances = MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
        .with_arbiter(default_arbiter())
        .with_merchant_public_key(XmrPoint::generator())
        .with_random_channel_nonce(&mut OsRng)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap());
    assert!(matches!(no_balances.build(), Err(MissingSeedInfo::InitialBalances)));

    let no_key = MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
        .with_arbiter(default_arbiter())
        .with_initial_balances(test_balances())
        .with_random_channel_nonce(&mut OsRng)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap());
    assert!(matches!(no_key.build(), Err(MissingSeedInfo::MerchantPublicKey)));

    let no_nonce = MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
        .with_arbiter(default_arbiter())
        .with_initial_balances(test_balances())
        .with_merchant_public_key(XmrPoint::generator())
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap());
    assert!(matches!(no_nonce.build(), Err(MissingSeedInfo::ChannelNonce)));

    let no_address = MerchantSeedBuilder::<crate::Ed25519>::new(Network::Mainnet)
        .with_arbiter(default_arbiter())
        .with_initial_balances(test_balances())
        .with_merchant_public_key(XmrPoint::generator())
        .with_random_channel_nonce(&mut OsRng);
    assert!(matches!(no_address.build(), Err(MissingSeedInfo::ClosingAddress)));
}

/// Two seeds built with `with_random_channel_nonce` draw independent nonces.
///
/// Locks in the property the CSPRNG setter exists for: a future change that turns the nonce into a
/// constant or a counter fails here instead of silently un-blinding every channel id.
#[test]
fn random_channel_nonce_differs_per_seed() {
    let (first, _) = build_merchant_seed();
    let (second, _) = build_merchant_seed();
    assert_ne!(first.merchant_nonce, second.merchant_nonce);
}

/// A seed may offer several arbiters; the customer is free to pick any of them.
#[test]
fn customer_may_pick_any_offered_arbiter() {
    let merchant_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let seed: MerchantSeedInfo = MerchantSeedBuilder::new(Network::Mainnet)
        .with_arbiters([arbiter(1), arbiter(2)])
        .with_initial_balances(test_balances())
        .with_merchant_public_key(XmrPoint::generator() * *merchant_secret)
        .with_random_channel_nonce(&mut OsRng)
        .with_closing_address(MERCHANT_ADDRESS.parse().unwrap())
        .build()
        .expect("to build merchant seed info");

    let customer_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let proposer = ChannelProposer::new(
        seed,
        arbiter(2),
        customer_secret,
        Curve25519Secret::random(&mut OsRng),
        CUSTOMER_ADDRESS.parse().unwrap(),
        OsRng.next_u64(),
    )
    .expect("the second offered arbiter is acceptable");
    assert_eq!(proposer.metadata.arbiter_configuration(), &arbiter(2));
}

/// C1: The customer cannot propose an arbiter the merchant never offered.
#[test]
fn customer_rejects_unoffered_arbiter() {
    let (seed, _merchant_secret) = build_merchant_seed();
    let customer_secret = Zeroizing::new(XmrScalar::random(&mut OsRng));
    let err = ChannelProposer::new(
        seed,
        arbiter(99),
        customer_secret,
        Curve25519Secret::random(&mut OsRng),
        CUSTOMER_ADDRESS.parse().unwrap(),
        OsRng.next_u64(),
    )
    .expect_err("an arbiter outside the seed's offer must be refused");
    assert!(matches!(err, ProposeProtocolError::ArbiterNotAccepted(id) if id == "arbiter-99"));
}

// ====================== M2: ReceiveProposal::receive_proposal ======================

/// M2: Merchant rejects a proposal naming an arbiter that its seed does not offer.
#[test]
fn merchant_rejects_unoffered_arbiter() {
    let (seed, merchant_secret) = build_merchant_seed();
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    proposal.channel_id = swap_arbiter(&proposal, arbiter(7));
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::MismatchedArbiterConfig));
}

/// M2: The dispute window is part of the agreement, so an arbiter differing only in its window is refused.
#[test]
fn merchant_rejects_stretched_dispute_window() {
    let (seed, merchant_secret) = build_merchant_seed();
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    let stretched = ArbiterConfiguration::new(
        *default_arbiter().master_public_key(),
        default_arbiter().canister_id(),
        Duration::from_secs(10),
    );
    let tampered_id = swap_arbiter(&proposal, stretched);
    // The arbiter is not in the id transcript, so the channel id is untouched by the swap.
    assert_eq!(tampered_id.name(), proposal.channel_id.name());
    proposal.channel_id = tampered_id;
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::MismatchedArbiterConfig));
}

/// M2: Merchant rejects a proposal with tampered seed info.
#[test]
fn merchant_rejects_tampered_seed() {
    let (seed, merchant_secret) = build_merchant_seed();
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    // Tamper with the echoed seed's merchant nonce. The fixture nonce is random, so flip a bit to
    // guarantee a different value rather than relying on a fixed constant not colliding.
    proposal.seed.merchant_nonce ^= 1;
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::SeedMismatch));
}

/// M2: Merchant rejects a proposal whose echoed seed advertises a different arbiter offer.
#[test]
fn merchant_rejects_tampered_arbiter_offer() {
    let (seed, merchant_secret) = build_merchant_seed();
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    proposal.seed.accepted_arbiters.push(arbiter(7));
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::SeedMismatch));
}

/// M2: Merchant rejects a proposal with zero total balance.
#[test]
fn merchant_rejects_zero_balance() {
    let (seed, merchant_secret) = build_merchant_seed_with_balances(zero_balances());
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
    let (seed, _merchant_secret) = build_merchant_seed();
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Rejected(RejectProposalReason::new("Not interested"));
    let closed = customer.handle_response(response).unwrap_err();
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

/// C2: Customer rejects an acceptance carrying a channel ID they did not compute.
///
/// If the merchant returns an acceptance with a channel ID that doesn't match the one the
/// customer computed (e.g. because the merchant used a different key), the customer closes.
#[test]
fn customer_rejects_tampered_key_in_acceptance() {
    let (seed, _merchant_secret) = build_merchant_seed();
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Accepted(fake_channel_id());
    let closed = customer.handle_response(response).unwrap_err();
    assert!(matches!(closed.reason(), ChannelClosedReason::Rejected(_)));
}

/// C2: AwaitingProposalResponse can timeout to Closed.
#[test]
fn awaiting_response_timeout() {
    let (seed, _merchant_secret) = build_merchant_seed();
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
    let (seed, merchant_secret) = build_merchant_seed();
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
    let (seed, merchant_secret) = build_merchant_seed();
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
    let (seed, merchant_secret) = build_merchant_seed();
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
    let (merchant, customer) = propose_channel();
    assert_eq!(merchant.metadata.channel_id().name(), customer.metadata.channel_id().name());
}

/// Merchant and customer have the correct roles after establishing.
#[test]
fn established_roles_are_correct() {
    let (merchant, customer) = propose_channel();
    assert_eq!(merchant.metadata.role(), ChannelRole::Merchant);
    assert_eq!(customer.metadata.role(), ChannelRole::Customer);
}

/// Closing during the proposal phase preserves the initial balances as final balances.
#[test]
fn rejection_preserves_initial_balances() {
    let (seed, _merchant_secret) = build_merchant_seed();
    let customer = customer_creates_proposal(seed);
    let (customer, _proposal) = customer.into_proposal();
    let response = ProposalResponse::Rejected(RejectProposalReason::new("Declined"));
    let closed = customer.handle_response(response).unwrap_err();
    assert_eq!(closed.final_balances(), test_balances());
}

/// Tampered seed with a modified closing address is also detected.
#[test]
fn merchant_rejects_tampered_closing_address() {
    let (seed, merchant_secret) = build_merchant_seed();
    let partial_spend_key = Curve25519Secret::random(&mut OsRng);
    let merchant: AwaitProposal = AwaitProposal::new(seed.clone(), merchant_secret, partial_spend_key);
    let customer = customer_creates_proposal(seed);
    let (_customer, mut proposal) = customer.into_proposal();
    // Tamper with the closing address in the echoed seed
    proposal.seed.merchant_closing_address = CUSTOMER_ADDRESS.parse().unwrap();
    let err = merchant.receive_proposal(proposal).unwrap_err();
    assert!(matches!(err, InvalidProposal::SeedMismatch));
}