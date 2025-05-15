use crate::amount::MoneroAmount;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

pub struct MoneroViewKey;
pub struct MoneroTransaction;

// re-export
pub use monero::Address as MoneroAddress;

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(bound(deserialize = "T: for<'des> Deserialize<'des>", serialize = "T: Serialize",))]
pub struct RequestEnvelope<T>
where
    T: Clone + Debug,
{
    pub channel: String,
    pub payload: T,
}

impl<T> RequestEnvelope<T>
where
    T: Clone + Debug,
{
    pub fn new(channel: String, payload: T) -> Self {
        Self { channel, payload }
    }

    pub fn channel_name(&self) -> String {
        self.channel.clone()
    }

    pub fn open(self) -> (String, T) {
        (self.channel, self.payload)
    }
}

/// The first set of data shared between wallets in generating a new multisig wallet.
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct MultiSigInitInfo {
    // Something like MultisigxV2R1C9Bd2LN...
    pub init: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MultisigKeyInfo {
    // Something like MultisigxV2R1C9Bd2LN...
    pub key: String,
}

impl Debug for MultisigKeyInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiSigKeyInfo(****)")
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PartialKeyImage;

#[derive(Clone, Deserialize, Serialize)]
pub struct PartiallySignedMoneroTransaction;
pub struct MoneroPeer;
pub struct MultiSigSeed;

#[derive(Debug, Clone, Default)]
pub struct WalletBalance {
    pub total: MoneroAmount,
    pub spendable: MoneroAmount,
    pub blocks_left: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionId {
    pub id: String,
}

impl TransactionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}
