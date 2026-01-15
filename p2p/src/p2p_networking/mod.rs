//! Low-level P2P networking infrastructure.
//!
//! This module provides the foundational networking primitives for Grease's peer-to-peer
//! communication layer. It is designed to be protocol-agnostic and handles the mechanics
//! of connection management, event processing, and request-response patterns.
//!
//! # Architecture
//!
//! The module is structured around three main components:
//!
//! - [`EventLoop`]: The core network event processor that runs in its own async task, handling
//!   libp2p swarm events and routing commands from higher-level components.
//!
//! - [`RequestResponseHandler`]: A trait defining how to process incoming request-response
//!   messages. Implement this for custom message types.
//!
//! - [`AsyncReqResponseHandler`]: A wrapper that bridges libp2p's event-driven model with
//!   async/await patterns, managing pending requests and response delivery.
//!
//! # Design Principles
//!
//! This module is **closed for modification**. Application-specific logic (Grease protocol
//! handlers, business rules, etc.) belongs in [`super::behaviour`] or higher-level modules.
//! Only generic networking infrastructure should be added here.
//!
//! # Key Types
//!
//! - [`PendingRequests`]: Tracks outbound requests awaiting responses
//! - [`InboundForwarder`]: Forwards inbound requests to application handlers via channels
//! - [`RemoteRequest`]: Wraps an inbound request with its response channel
//! - [`NetworkCommand`]: Commands sent to the event loop (dial, listen, send message, etc.)
//! - [`PeerConnectionError`]: Error types for connection and protocol failures

mod async_wrapper;
mod event_loop;
mod request_response;

pub use async_wrapper::{AsyncAPI, AsyncReqResponseHandler, InboundForwarder, PendingRequests};
pub use event_loop::{EventLoop, NetworkCommand, PeerConnectionError, RemoteRequest};
pub use request_response::RequestResponseHandler;
