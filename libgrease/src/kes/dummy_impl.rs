use crate::kes::traits::{KesError, KesIinitializationRecord};
use crate::kes::KeyEscrowService;
use log::info;
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyKes;

impl KeyEscrowService for DummyKes {
    fn initialize(_init: KesIinitializationRecord) -> impl Future<Output = Result<Self, KesError>> + Send {
        async {
            info!("Dummy KES initialized");
            Ok(DummyKes)
        }
    }
}
