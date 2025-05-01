use crate::amount::MoneroAmount;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum UpdateError {
    #[error("There are insufficient funds in the channel to make the desired payment")]
    InsufficientFunds { available: MoneroAmount, required: MoneroAmount },
    #[error("The total balance of the channel would change if the update was applied")]
    NotBalanced,
}

impl UpdateError {
    pub fn insufficient_funds(available: MoneroAmount, required: MoneroAmount) -> Self {
        UpdateError::InsufficientFunds { available, required }
    }
}
