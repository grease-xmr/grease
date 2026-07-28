/// The scalar-field curve inherited from the retired VCOF cross-curve design.
///
/// The state layer is monomorphized over this alias; the VCOF-deletion ticket swaps or
/// removes it in this one place.
pub(crate) type SfCurve = grease_grumpkin::Grumpkin;

/// A channel witness scalar on the retired VCOF curve.
pub(crate) type Witness = crate::cryptography::CrossCurveScalar<SfCurve>;

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
