#[cfg(feature = "dummy_channel")]
pub mod dummy_impl;

mod error;
mod status;
mod traits;

pub use error::UpdateError;
pub use status::{ChannelUpdateStatus, PaymentResponse};
pub use traits::{ActivePaymentChannel, ChannelPayment, ClosedPaymentChannel};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    Merchant,
    Customer,
}
