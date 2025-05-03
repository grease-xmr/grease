use crate::kes::KeyEscrowService;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyKes;

impl KeyEscrowService for DummyKes {}
