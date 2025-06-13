use crate::amount::{MoneroAmount, MoneroDelta};
use monero::{Address, Error as AddressError, Network, PrivateKey, PublicKey, ViewPair};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
// re-export
use crate::balance::Balances;
use crate::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use crate::crypto::zk_objects::{KesProof, PartialEncryptedKey};
use crate::payment_channel::ChannelRole;

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

#[derive(Clone, Deserialize, Serialize)]
pub struct PartialKeyImage;

#[derive(Clone, Deserialize, Serialize)]
pub struct PartiallySignedMoneroTransaction;
pub struct MoneroPeer;
pub struct MultiSigSeed;

#[derive(Debug, Clone, Default)]
pub struct WalletBalance {
    pub total: MoneroDelta,
    pub spendable: MoneroDelta,
    pub blocks_left: usize,
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

/// A channel update template before any proofs have been generated.
///
/// It is based on the current channel state, plus the delta to be applied to the merchant's balance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChannelSecrets {
    /// The update counter for the channel. This is incremented every time a new update is sent. The initial balance
    /// represents update 0.
    pub update_count: u64,
    /// The balances after applying the delta to the current balances
    pub new_balances: Balances,
    /// The change in the *Merchant's* balance
    pub delta: MoneroDelta,
    /// The last witness value on the L2 curve
    pub witness: Vec<u8>,
    /// The last statement value on the L2 curve
    pub statement: Vec<u8>,
    /// The equivalent secret value on Ed25519
    pub secret: Curve25519Secret,
    /// The last public key on the Ed25519 curve
    pub public_key: Curve25519PublicKey,
}

/// Channel Update result record
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Updated {
    /// The new channel balances after the update
    pub new_balances: Balances,
    /// The update count for the channel
    pub update_count: u64,
    /// The change that was effected in the merchant's balance
    pub delta: MoneroDelta,
}

/// A struct to make it easier to persist and pass wallet info around. Obviously it needs to be made more secure for
/// a production environment.
#[derive(Clone, Serialize, Deserialize)]
pub struct MultisigWalletData {
    pub my_spend_key: Curve25519Secret,
    pub my_public_key: Curve25519PublicKey,
    pub sorted_pubkeys: [Curve25519PublicKey; 2],
    pub joint_private_view_key: Curve25519Secret,
    pub joint_public_spend_key: Curve25519PublicKey,
    pub birthday: u64,
    pub known_outputs: String,
}

impl MultisigWalletData {
    pub fn peer_public_key(&self) -> &Curve25519PublicKey {
        if self.my_public_key == self.sorted_pubkeys[0] {
            &self.sorted_pubkeys[1]
        } else {
            &self.sorted_pubkeys[0]
        }
    }

    pub fn address(&self, network: Network) -> Address {
        let spend = PublicKey { point: *self.joint_public_spend_key.as_compressed() };
        let view = PrivateKey { scalar: *self.joint_private_view_key.as_scalar() };
        let keys = ViewPair { spend, view };
        Address::from_viewpair(network, &keys)
    }
}

impl Debug for MultisigWalletData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultisigWalletData( ")?;
        write!(f, "my_public_key: {}, ", self.my_public_key.as_hex())?;
        write!(
            f,
            "sorted_pubkeys: [{}, {}], ",
            self.sorted_pubkeys[0].as_hex(),
            self.sorted_pubkeys[1].as_hex()
        )?;
        write!(f, "birthday: {}, ", self.birthday)?;
        write!(f, "known_outputs: {}, ", self.known_outputs)?;
        write!(f, ")")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingTransaction {
    pub role: ChannelRole,
    pub transaction_id: TransactionId,
    pub amount: MoneroAmount,
}

impl FundingTransaction {
    pub fn new(role: ChannelRole, txid: impl Into<String>, amount: impl Into<MoneroAmount>) -> Self {
        FundingTransaction { role, transaction_id: TransactionId::new(txid), amount: amount.into() }
    }
}

#[derive(Debug)]
pub struct TransactionRecord {
    pub channel_name: String,
    pub transaction_id: TransactionId,
    pub amount: MoneroAmount,
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
