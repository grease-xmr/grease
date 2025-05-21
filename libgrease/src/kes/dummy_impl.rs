use crate::crypto::traits::PublicKey;
use crate::kes::data_objects::KesInitializationResult;
use crate::kes::error::KesError;
use crate::kes::{KesInitializationRecord, KeyEscrowService};
use log::*;
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DummyKes;

impl KeyEscrowService for DummyKes {
    async fn initialize<P: PublicKey>(
        &self,
        init: KesInitializationRecord<P>,
    ) -> Result<KesInitializationResult, KesError> {
        info!("Dummy KES initialized");
        let result = KesInitializationResult { id: init.channel_id.into() };
        Ok(result)
    }

    fn verify(&self, _init: KesInitializationResult) -> impl Future<Output = Result<bool, KesError>> + Send {
        async {
            info!("Dummy KES verified");
            Ok(true)
        }
    }
}
