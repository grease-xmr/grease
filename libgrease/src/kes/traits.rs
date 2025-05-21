use crate::crypto::traits::PublicKey;
use crate::kes::data_objects::KesInitializationResult;
use crate::kes::error::KesError;
use crate::kes::KesInitializationRecord;
use serde::{Deserialize, Serialize};
use std::future::Future;

pub trait KeyEscrowService: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Create a new escrow with the information in `init`.
    fn initialize<P: PublicKey>(
        &self,
        init: KesInitializationRecord<P>,
    ) -> impl Future<Output = Result<KesInitializationResult, KesError>> + Send;

    /// Verify the KES using the information given.
    fn verify(&self, init: KesInitializationResult) -> impl Future<Output = Result<bool, KesError>> + Send;
}
