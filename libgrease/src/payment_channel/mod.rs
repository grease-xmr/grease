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
