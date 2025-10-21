use crate::amount::{MoneroAmount, MoneroDelta};
use monero::{Address, Error as AddressError};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
// re-export
use crate::balance::Balances;
use crate::crypto::keys::Curve25519PublicKey;
use crate::crypto::zk_objects::{KesProof, PartialEncryptedKey};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultisigSplitSecrets {
    /// The encrypted secret shard for the peer
    pub peer_shard: PartialEncryptedKey,
    /// The encrypted secret shard for the KES
    pub kes_shard: PartialEncryptedKey,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultisigSplitSecretsResponse {
    /// The encrypted secret shard for the peer
    pub peer_shard: PartialEncryptedKey,
    /// The encrypted secret shard for the KES
    pub kes_shard: PartialEncryptedKey,
    /// The proof/signature that the KES was constructed correctly
    pub kes_proof: KesProof,
}

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

#[derive(Clone, Deserialize, Serialize)]
pub struct MultisigKeyInfo {
    pub key: Curve25519PublicKey,
}

impl Debug for MultisigKeyInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiSigKeyInfo(****)")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct TransactionId {
    pub id: String,
}

impl Display for TransactionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl TransactionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Channel Update result record
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FinalizedUpdate {
    /// The new channel balances after the update
    pub new_balances: Balances,
    /// The update count for the channel
    pub update_count: u64,
    /// The change that was effected in the merchant's balance
    pub delta: MoneroDelta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub channel_name: String,
    pub transaction_id: TransactionId,
    pub amount: MoneroAmount,
    // The serialized WalletOutput that can be imported into MultisigWallet
    pub serialized: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClosingAddresses {
    pub customer: Address,
    pub merchant: Address,
}

impl ClosingAddresses {
    pub fn new(customer: &str, merchant: &str) -> Result<Self, AddressError> {
        let customer = Address::from_str(customer)?;
        let merchant = Address::from_str(merchant)?;
        Ok(Self { customer, merchant })
    }

    pub fn customer(&self) -> &Address {
        &self.customer
    }

    pub fn merchant(&self) -> &Address {
        &self.merchant
    }
}
