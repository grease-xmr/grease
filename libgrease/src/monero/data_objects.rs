use crate::amount::MoneroAmount;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

pub struct MoneroViewKey;
pub struct MoneroTransaction;

// re-export
use crate::monero::MoneroKeyPair;
use crate::state_machine::VssOutput;
pub use monero::Address as MoneroAddress;

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(bound(deserialize = "T: for<'des> Deserialize<'des>", serialize = "T: Serialize",))]
pub struct MessageEnvelope<T>
where
    T: Clone + Debug,
{
    pub channel: String,
    pub payload: T,
}

impl<T> MessageEnvelope<T>
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
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultiSigInitInfo {
    // Something like MultisigxV2R1C9Bd2LN...
    pub init: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MultisigKeyInfo {
    // Something like MultisigxV2R1C9Bd2LN...
    pub key: String,
}

/// When the customer returns the multisig key to the merchant, it also includes the VSS info
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MsKeyAndVssInfo {
    pub multisig_key: MultisigKeyInfo,
    pub shards_for_merchant: VssOutput,
}

/// The merchant send this to the customer to confirm the multisig wallet address and share its split secrets
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletConfirmation {
    pub address: MoneroAddress,
    pub merchant_vss_info: VssOutput,
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

pub struct WalletInfo {
    // The address of the multisig wallet.
    pub address: MoneroAddress,
    // My keypair for the multisig wallet
    pub keypair: MoneroKeyPair,
    // The encrypted secret shards of my spendkey that has been shared with the peer and KES
    pub peer_vss_info: VssOutput,
    // The encrypted secret shards of my peer's spendkey that has been shared with me
    pub my_vss_info: VssOutput,
}
