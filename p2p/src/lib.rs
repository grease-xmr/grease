//! # Grease P2P Network Server
//!
//! The major components of this crate are:
//! * [`NetworkServer`]
//! * [`Client`]
//! * [`EventLoop`]
//!
//! ## NetworkServer
//!
//! The `NetworkServer` is the public-facing API to grease. It abstracts most of the complicated peer-to-peer
//! networking, cryptography, and state machine logic behind simple asynchronous method calls.
//!
//! For example, to establish a new channel with a peer, you would call:
//! ```rust, no_run
//!  let proposal = create_channel_proposal(oob_info, address)?;
//!  // Send the proposal to the merchant and wait for reply
//!  let name = server.establish_new_channel(proposal).await?;
//! ```
//! `establish_new_channel` takes care of all the underlying details, such as connecting to the peer,
//! negotiating the channel parameters, and setting up the payment channel.
//!
//! ## Client
//!
//! The `Client` is a lightweight abstraction that allows you to interact with the `EventLoop`.
//! It provides methods to connect to peers, send messages, and manage channels.
//!
//! [`Client`] does not carry out any work itself. It simply forwards commands to the [`EventLoop`],
//! waits for the results, and returns them to the caller. [`Client`] is designed to be cheaply clonable, and is used
//! heavily in [`NetworkServer`] to interact with the network in carrying out the application logic.
//!
//! ## EventLoop
//!
//! The `EventLoop` is the core of the networking logic. The `EventLoop` handles network events and remote commands
//! for the Grease p2p network communications. It runs in its own asynchronous task and communicates
//! with the `Client` via channels.
//!
//! The `EventLoop` is only a data broker. It does not do any business or application logic itself. This is all
//! delegated to one [`NetworkServer`].

mod behaviour;
pub mod delegates;
pub mod errors;
mod event_loop;
mod identity;
mod key_manager;
pub mod message_types;
mod network_client;
mod payment_channel;
mod pending_updates;
mod server;

pub use delegates::traits::GreaseChannelDelegate;
pub use event_loop::EventLoop;
pub use identity::{ContactInfo, ConversationIdentity, IdentityError};
pub use key_manager::KeyManager;
pub use message_types::{ClientCommand, GreaseRequest, GreaseResponse, PeerConnectionEvent};
pub use network_client::{new_network, Client, PeerConnection};
pub use payment_channel::{OutOfBandMerchantInfo, PaymentChannel, PaymentChannels};
pub use server::{EventHandlerOptions, NetworkServer, WritableState};
