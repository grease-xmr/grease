use crate::state_machine::Balances;
use serde::{Deserialize, Serialize};
use std::future::Future;
use thiserror::Error;

pub struct PartialEncryptedKey(pub String);

pub struct KesIinitializationRecord {
    pub kes_public_key: String,
    pub channel_id: String,
    pub initial_balances: Balances,
    pub merchant_key: PartialEncryptedKey,
    pub customer_key: PartialEncryptedKey,
}

#[derive(Clone, Debug, Error)]
pub enum KesError {
    #[error("KES initialization failed: {0}")]
    InitializationError(String),
}

pub trait KeyEscrowService: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    fn initialize(init: KesIinitializationRecord) -> impl Future<Output = Result<Self, KesError>> + Send;
}
