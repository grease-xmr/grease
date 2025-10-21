//! The Channel Opening Protocol
//!
//! Opening a channel is, by some distance, the most complex part of the Grease Payment Channel Protocol.
//!
//! Opening a channel goes through many steps:
//!
//! 1. Use Serai infrastructure to create a multisig wallet between the customer and merchant.
//!    We call the spending key of each party the *witness*, denoted $\omega_0$.

use crate::grease_protocol::error::GreaseProtocolError;

pub fn create_adapter_signature() {
    todo!()
}

pub fn verify_adapter_signature() {
    todo!()
}

pub async fn generate_kes_witness_proof() -> Result<(), GreaseProtocolError> {
    todo!()
}

pub async fn verify_kes_witness_proof() -> Result<(), GreaseProtocolError> {
    todo!()
}
