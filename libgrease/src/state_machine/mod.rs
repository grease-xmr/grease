// Lifecycle state machines
mod closed_channel;
mod closing_channel;
mod disputing_channel;
mod establishing_channel;
pub mod lifecycle;
mod open_channel;
mod proposing_channel;

pub mod error;
mod events;
pub mod multisig_setup;
mod timeouts;

// Might want to move these
mod commitment_tx;

pub use closed_channel::{ChannelClosedReason, ClosedChannelState};
pub use closing_channel::{ChannelCloseRecord, ClosingChannelState};
pub use disputing_channel::{DisputeReason, DisputingChannelState, DEFAULT_DISPUTE_WINDOW};
pub(crate) use establishing_channel::commitment_transaction_message;
pub use establishing_channel::{
    CustomerEstablishing, DefaultEstablishingState, EstablishingState, MerchantEstablishing,
};
pub use events::LifeCycleEvent;
pub use lifecycle::{DefaultChannelState, LifecycleStage};
pub use multisig_setup::{CustomerSetup, CustomerStage, MerchantSetup, MerchantStage, MultisigSetupError, SetupState};
pub use open_channel::{EstablishedChannelState, UpdateRecord};
pub use proposing_channel::{
    AwaitProposal, AwaitingConfirmation, AwaitingProposalResponse, ChannelProposer, MerchantSeedInfo,
    NewChannelProposal, ProposalConfirmed, ProposalResponse, RejectProposalReason,
};
pub use timeouts::TimeoutReason;

pub use commitment_tx::CommitmentTransaction;

// Re-export MerchantSeedBuilder and provide a backwards-compatible alias
pub use crate::grease_protocol::propose_channel::MerchantSeedBuilder;
pub type ChannelSeedBuilder = MerchantSeedBuilder<ciphersuite::Ed25519>;
