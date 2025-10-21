//! The Grease Payment Channel Protocol
//!
//! This module describes the generic procedures for the Grease Payment Channel Protocol.
//!
//! It is split into five modules:
//! 1. open: Procedures for opening a payment channel between a customer and a merchant.
//! 2. update: Procedures for updating the state of an existing payment channel.
//! 3. close: Procedures for closing a payment channel and settling on-chain.
//! 4. force_close: Procedures for force-closing a payment channel in case one of the counterparties is unresponsive.
//! 5. dispute: Procedure to handle the dispute of a force-closing channel.

pub mod close;
pub mod dispute;
pub mod force_close;
pub mod open;
pub mod update;
