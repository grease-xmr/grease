use crate::amount::{MoneroAmount, MoneroDelta};
use crate::channel_id::ChannelId;
use crate::monero::error::ClosingAddressError;
use monero::Address;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;
// re-export
use crate::balance::Balances;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::cryptography::zk_objects::{KesProof, PartialEncryptedKey};
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
    pub channel: ChannelId,
    pub payload: T,
}

impl<T> MessageEnvelope<T>
where
    T: Clone + Debug,
{
    pub fn new(channel: ChannelId, payload: T) -> Self {
        Self { channel, payload }
    }

    pub fn channel_id(&self) -> &ChannelId {
        &self.channel
    }

    pub fn open(self) -> (ChannelId, T) {
        (self.channel, self.payload)
    }
}

#[deprecated = "Use SharedPublicKey instead"]
#[derive(Clone, Deserialize, Serialize)]
pub struct MultisigKeyInfo {
    pub key: Curve25519PublicKey,
    pub role: ChannelRole,
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
    pub fn new(customer: &str, merchant: &str) -> Result<Self, ClosingAddressError> {
        let customer = Address::from_str(customer).map_err(|e| ClosingAddressError::InvalidAddress(e.to_string()))?;
        let merchant = Address::from_str(merchant).map_err(|e| ClosingAddressError::InvalidAddress(e.to_string()))?;
        if customer == merchant {
            return Err(ClosingAddressError::IdenticalAddresses);
        }
        if customer.network != merchant.network {
            return Err(ClosingAddressError::NetworkMismatch {
                customer: customer.network,
                merchant: merchant.network,
            });
        }
        Ok(Self { customer, merchant })
    }

    pub fn customer(&self) -> &Address {
        &self.customer
    }

    pub fn merchant(&self) -> &Address {
        &self.merchant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGENET_ALICE: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const STAGENET_BOB: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";
    const TESTNET_ALICE: &str =
        "9wviCeWe2D8XS82k2ovp5EUYLzBt9pYNW2LXUFsZiv8S3Mt21FZ5qQaAroko1enzw3eGr9qC7X1D7Geoo2RrAotYPwq9Gm8";

    #[test]
    fn closing_addresses_valid() {
        let result = ClosingAddresses::new(STAGENET_ALICE, STAGENET_BOB);
        assert!(result.is_ok());
        let addresses = result.unwrap();
        assert_eq!(addresses.customer().to_string(), STAGENET_ALICE);
        assert_eq!(addresses.merchant().to_string(), STAGENET_BOB);
    }

    #[test]
    fn closing_addresses_rejects_identical_addresses() {
        let result = ClosingAddresses::new(STAGENET_ALICE, STAGENET_ALICE);
        assert!(matches!(result, Err(ClosingAddressError::IdenticalAddresses)));
    }

    #[test]
    fn closing_addresses_rejects_network_mismatch() {
        let result = ClosingAddresses::new(STAGENET_ALICE, TESTNET_ALICE);
        assert!(matches!(result, Err(ClosingAddressError::NetworkMismatch { .. })));
    }

    #[test]
    fn closing_addresses_rejects_invalid_address() {
        let result = ClosingAddresses::new("invalid_address", STAGENET_BOB);
        assert!(matches!(result, Err(ClosingAddressError::InvalidAddress(_))));

        let result = ClosingAddresses::new(STAGENET_ALICE, "also_invalid");
        assert!(matches!(result, Err(ClosingAddressError::InvalidAddress(_))));
    }
}
