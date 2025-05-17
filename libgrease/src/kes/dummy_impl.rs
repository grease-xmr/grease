use crate::kes::traits::{KesError, KesIinitializationRecord};
use crate::kes::KeyEscrowService;
use log::info;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyKes;

impl KeyEscrowService for DummyKes {
    async fn initialize(_init: KesIinitializationRecord) -> Result<Self, KesError> {
        info!("Dummy KES initialized");
        Ok(DummyKes)
    }
}
