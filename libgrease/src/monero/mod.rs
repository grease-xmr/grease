#[cfg(feature = "dummy_channel")]
pub mod dummy_impl;
pub mod error;
mod traits;

pub use traits::{MultiSigService, MultiSigWallet};
