//! Channel Update Protocol Traits
//!
//! This module defines traits for the channel update phase, where parties exchange
//! new balances, VCOF proofs, and adapter signatures to update the channel state.

use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::vcof::{VcofError, VerifiableConsecutiveOnewayFunction};
use crate::grease_protocol::adapter_signature::{AdapterSignatureError, AdapterSignatureHandler};
use crate::grease_protocol::error::DleqError;
use crate::payment_channel::HasRole;
use async_trait::async_trait;
use ciphersuite::Ed25519;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Package containing all data needed for a channel update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePackage {
    /// The update count this package is for
    pub update_count: u64,
    /// The adapted signature for the closing transaction at this state
    pub adapted_signature: AdaptedSignature<Ed25519>,
    /// Serialized VCOF proof demonstrating valid witness derivation
    pub vcof_proof: Vec<u8>,
    /// Preprocessing data for the Monero transaction
    pub preprocess: Vec<u8>,
}

/// Common functionality shared by both update proposer and proposee.
#[async_trait]
pub trait UpdateProtocolCommon<C: FrostCurve>: HasRole + AdapterSignatureHandler + Send + Sync {
    type VCOF: VerifiableConsecutiveOnewayFunction<C>;

    /// Returns a reference to the VCOF instance.
    fn vcof(&self) -> &Self::VCOF;

    /// Returns the current update count.
    fn update_count(&self) -> u64;

    /// Derive the next witness value using the VCOF.
    ///
    /// This operation may involve ZK proof generation and is therefore async.
    async fn derive_next_witness(&mut self) -> Result<(), UpdateProtocolError>;

    /// Create a VCOF proof for the current witness derivation.
    ///
    /// This operation involves ZK proof generation and is therefore async.
    async fn create_vcof_proof(&self) -> Result<Vec<u8>, UpdateProtocolError>;

    /// Verify a VCOF proof from the peer.
    ///
    /// This operation may involve ZK proof verification and is therefore async.
    ///
    /// # Arguments
    /// * `proof` - The serialized VCOF proof
    /// * `peer_q_prev` - The peer's previous public commitment (Q_{i-1})
    /// * `peer_q_curr` - The peer's current public commitment (Q_i)
    async fn verify_vcof_proof(
        &self,
        proof: &[u8],
        peer_q_prev: &C::G,
        peer_q_curr: &C::G,
    ) -> Result<(), UpdateProtocolError>;

    /// Verify the peer's adapted signature.
    fn verify_peer_adapted_signature(
        &self,
        sig: &AdaptedSignature<Ed25519>,
        msg: &[u8],
    ) -> Result<(), UpdateProtocolError>;
}

/// Protocol trait for the update proposer (initiator).
///
/// The proposer initiates a channel update by specifying a balance delta,
/// generating necessary cryptographic material, and finalizing after receiving
/// the peer's response.
pub trait UpdateProtocolProposer<C: FrostCurve>: UpdateProtocolCommon<C> {
    /// Initiate a channel update with the given balance delta.
    ///
    /// A positive delta transfers funds from customer to merchant,
    /// a negative delta transfers from merchant to customer.
    fn initiate_update(&mut self, delta: i64) -> Result<(), UpdateProtocolError>;

    /// Generate transaction preprocessing data.
    fn generate_tx_preprocessing<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<u8>, UpdateProtocolError>;

    /// Create the update package to send to the peer.
    fn create_update_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<UpdatePackage, UpdateProtocolError>;

    /// Process the response package from the peer.
    fn process_response(&mut self, response: &UpdatePackage) -> Result<(), UpdateProtocolError>;

    /// Finalize the update after successful exchange.
    ///
    /// Returns the new update count.
    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError>;

    /// Abort the update and rollback any pending state changes.
    fn abort_update(&mut self) -> Result<(), UpdateProtocolError>;
}

/// Protocol trait for the update proposee (responder).
///
/// The proposee receives update requests, validates them, and responds
/// with their own cryptographic material.
pub trait UpdateProtocolProposee<C: FrostCurve>: UpdateProtocolCommon<C> {
    /// Receive and validate an update request from the proposer.
    fn receive_update_request(&mut self, delta: i64) -> Result<(), UpdateProtocolError>;

    /// Process the proposer's transaction preprocessing data.
    ///
    /// Returns own preprocessing data to send back.
    fn process_tx_preprocessing(&mut self, preprocess: &[u8]) -> Result<Vec<u8>, UpdateProtocolError>;

    /// Process the update package from the proposer.
    fn process_update_package(&mut self, package: &UpdatePackage) -> Result<(), UpdateProtocolError>;

    /// Create the response package to send to the proposer.
    fn create_response<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<UpdatePackage, UpdateProtocolError>;

    /// Finalize the update after successful exchange.
    ///
    /// Returns the new update count.
    fn finalize_update(&mut self) -> Result<u64, UpdateProtocolError>;

    /// Reject the update with a reason.
    fn reject_update(&mut self, reason: &str) -> Result<(), UpdateProtocolError>;
}

/// Errors that can occur during the channel update protocol.
#[derive(Debug, Error)]
pub enum UpdateProtocolError {
    #[error("Update {0} has not been prepared")]
    NotReady(u64),

    #[error("Received invalid data from peer: {0}")]
    InvalidDataFromPeer(String),

    #[error("Witness derivation error: {0}")]
    WitnessError(#[from] DleqError),

    #[error("Missing required information: {0}")]
    MissingInformation(String),

    #[error("Adapter signature error: {0}")]
    SignatureError(#[from] AdapterSignatureError),

    #[error("VCOF error: {0}")]
    VcofError(#[from] VcofError),

    #[error("Insufficient balance: {0}")]
    InsufficientBalance(String),

    #[error("Update count mismatch: expected {expected}, got {actual}")]
    UpdateCountMismatch { expected: u64, actual: u64 },

    #[error("Update already in progress")]
    UpdateInProgress,

    #[error("No update in progress")]
    NoUpdateInProgress,

    #[error("Update was rejected: {0}")]
    UpdateRejected(String),

    #[error("Invalid balance delta: {0}")]
    InvalidDelta(String),

    #[error("Preprocessing error: {0}")]
    PreprocessingError(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),
}
