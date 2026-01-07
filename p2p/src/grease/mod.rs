//! The grease client.
//!
//! This module contains the  
//! - grease message broker, which handles P2P messaging between channel parties ([`client`] and [`grease_message_broker`])
//! - message types used in P2P communications
//! - the client API to interact with the event loop ([`network_client`])
//! - the payment channel object, which represents a payment channel between two parties and manages the state machine for the channel.
mod client;
mod grease_message_broker;
mod message_types;
mod network_client;
mod payment_channel;
mod pending_updates;

pub use client::{GreaseClient, GreaseClientError, GreaseClientOptions};
pub use grease_message_broker::GreaseChannelEvents;
pub use message_types::{
    AckFundingTxBroadcast, ChannelProposalResult, GreaseRequest, GreaseResponse, NewChannelMessage, PrepareUpdate,
    RejectChannelProposal, UpdateCommitted, UpdatePrepared,
};
pub use payment_channel::{OutOfBandMerchantInfo, PaymentChannel, PaymentChannels};
