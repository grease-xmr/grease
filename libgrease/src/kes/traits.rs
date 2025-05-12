use serde::{Deserialize, Serialize};

pub trait KeyEscrowService: Serialize + for<'de> Deserialize<'de> + Send + Sync {}
