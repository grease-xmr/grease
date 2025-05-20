use crate::kes::data_objects::KesInitializationResult;
use crate::kes::error::KesError;
use crate::kes::{KesInitializationRecord, KeyEscrowService};
use log::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DummyKes;

impl KeyEscrowService for DummyKes {
    async fn initialize(&self, init: KesInitializationRecord) -> Result<KesInitializationResult, KesError> {
        info!("Dummy KES initialized");
        let result = KesInitializationResult { id: init.channel_id.into() };
        Ok(result)
    }
}
