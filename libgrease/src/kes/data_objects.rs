use crate::crypto::traits::PublicKey;
use crate::state_machine::Balances;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEncryptedKey(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KesId(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct KesInitializationRecord<P: PublicKey> {
    pub kes_public_key: P,
    pub channel_id: String,
    pub initial_balances: Balances,
    pub merchant_key: PartialEncryptedKey,
    pub customer_key: PartialEncryptedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KesInitializationResult {
    pub id: KesId,
}

impl From<String> for KesId {
    fn from(channel_id: String) -> Self {
        KesId(channel_id)
    }
}
