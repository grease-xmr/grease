use log::warn;
use serde::{Deserialize, Serialize};
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::kes::{FundingTransaction, KesInitializationRecord, KesInitializationResult, PartialEncryptedKey};
use crate::monero::{MoneroKeyPair, MultiSigWallet};
use crate::monero::data_objects::ChannelSecrets;
use crate::payment_channel::ChannelRole;

//------------------------------------       KES Verified State      ------------------------------------------------//
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct KesVerifiedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub channel_info: ChannelMetadata<P>,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_keypair",
        serialize_with = "crate::monero::helpers::serialize_keypair"
    )]
    pub wallet_secret: MoneroKeyPair,
    /// The encrypted secrets of *my* multisig wallet spend key
    pub peer_shards: PartialEncryptedKey,
    /// The encrypted secrets of *my peer's* multisig wallet spend key
    pub my_shards: PartialEncryptedKey,
    pub kes_info: KesInitializationRecord<P>,
    pub kes_verify_info: KesInitializationResult,
    pub wallet: W,
    /// The transaction ID of the merchant's funding transaction
    pub merchant_funding_tx: Option<FundingTransaction>,
    /// The transaction ID of the customer's funding transaction
    pub customer_funding_tx: Option<FundingTransaction>,
    pub(crate) initial_witness: Option<ChannelSecrets>,
}

impl<P, W> KesVerifiedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub fn kes_info(&self) -> KesInitializationRecord<P> {
        self.kes_info.clone()
    }

    pub fn save_funding_transaction(&mut self, tx: FundingTransaction) {
        match tx.role {
            ChannelRole::Merchant => {
                if let Some(old) = self.merchant_funding_tx.replace(tx) {
                    warn!(
                        "Merchant funding txid was already set to {} and has been replaced.",
                        old.transaction_id.id
                    );
                }
            }
            ChannelRole::Customer => {
                if let Some(old) = self.customer_funding_tx.replace(tx) {
                    warn!(
                        "Customer funding txid was already set to {} and has been replaced",
                        old.transaction_id.id
                    );
                }
            }
        }
    }
    /// Returns true if all necessary funding transactions are confirmed.
    ///
    /// This means that:
    /// - The merchant's funding transaction is confirmed (if the merchant's initial balance is not zero)
    /// - The customer's funding transaction is confirmed (if the customer's initial balance is not zero)
    pub fn are_funding_txs_confirmed(&self) -> bool {
        let initial_balances = self.channel_info.initial_balances;
        let merchant_ready = initial_balances.merchant.is_zero() || self.merchant_funding_tx.is_some();
        let customer_ready = initial_balances.customer.is_zero() || self.customer_funding_tx.is_some();
        // This is redundant, strictly speaking, because we don't allow both initial balances to be zero.
        let at_least_one_tx = self.merchant_funding_tx.is_some() || self.customer_funding_tx.is_some();
        merchant_ready && customer_ready && at_least_one_tx
    }

    /// Returns a record that can be used to interact and/or verify the KES state. Since the KES has already been
    /// verified, this record is always available.
    pub fn kes_verify_info(&self) -> KesInitializationResult {
        self.kes_verify_info.clone()
    }
}