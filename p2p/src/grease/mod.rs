//! The grease client.
//!
//! This module contains:
//! - Message types used in P2P communications ([`message_types`])
//! - The client API to interact with the event loop ([`network_client`])
//! - The payment channel object, which manages the state machine for the channel ([`payment_channel`])
mod client;
mod message_types;
mod network_client;
mod payment_channel;
mod pending_updates;

pub use client::{GreaseClient, GreaseClientError, GreaseClientOptions};
pub use message_types::{
    AckFundingTxBroadcast, ChannelProposalResult, GreaseRequest, GreaseResponse, NewChannelMessage, PrepareUpdate,
    RejectChannelProposal, UpdateCommitted, UpdatePrepared,
};
pub use network_client::{new_network, GreaseAPI, GreaseRemoteEvent};
pub use payment_channel::{OutOfBandMerchantInfo, PaymentChannel, PaymentChannels};
