#[cfg(feature = "dummy_channel")]
pub mod dummy_impl;

mod error;
mod status;
mod traits;

pub use error::UpdateError;
use serde::{Deserialize, Serialize};
pub use status::{ChannelUpdateStatus, PaymentResponse};
pub use traits::{ActivePaymentChannel, ChannelPayment, ClosedPaymentChannel};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRole {
    Merchant,
    Customer,
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
