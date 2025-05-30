mod error;

pub use error::UpdateError;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRole {
    Merchant,
    Customer,
}

impl Display for ChannelRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelRole::Merchant => write!(f, "Merchant"),
            ChannelRole::Customer => write!(f, "Customer"),
        }
    }
}

impl ChannelRole {
    pub fn other(&self) -> Self {
        match self {
            ChannelRole::Merchant => ChannelRole::Customer,
            ChannelRole::Customer => ChannelRole::Merchant,
        }
    }

    pub fn is_merchant(&self) -> bool {
        matches!(self, ChannelRole::Merchant)
    }

    pub fn is_customer(&self) -> bool {
        matches!(self, ChannelRole::Customer)
    }
}
