use serde::{Deserialize, Serialize};
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::kes::{KesInitializationRecord, KesInitializationResult};
use crate::monero::{MoneroKeyPair, MultiSigWallet};
use crate::monero::error::MoneroWalletError;
use crate::payment_channel::ChannelRole;
use crate::state_machine::{ChannelInitSecrets, VssOutput};

//------------------------------------     Wallet Created State      ------------------------------------------------//
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct WalletCreatedState<P, W>
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
    pub peer_shards: VssOutput,
    /// The encrypted secrets of *my peer's* multisig wallet spend key
    pub my_shards: VssOutput,
    pub kes_verify_info: Option<KesInitializationResult>,
    pub wallet: W,
}

impl<P, W> WalletCreatedState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    /// Returns the information needed to create the Verifiable Secret Sharing (VSS) record.
    ///
    /// In particular, it returns
    /// - our secret key
    /// - the public key of the merchant
    /// - the public key of the KES
    pub fn vss_info(&self) -> Result<ChannelInitSecrets<P>, MoneroWalletError> {
        let peer_public_key = match self.channel_info.role {
            ChannelRole::Merchant => self.channel_info.customer_pubkey.clone(),
            ChannelRole::Customer => self.channel_info.merchant_pubkey.clone(),
        };
        Ok(ChannelInitSecrets {
            channel_name: self.channel_info.channel_id.name(),
            wallet_secret: self.wallet_secret,
            peer_public_key,
            kes_public_key: self.channel_info.kes_public_key.clone(),
        })
    }

    /// Returns a records that can be used to interact and/or verify the KES state, if it has been created.
    pub fn kes_verify_info(&self) -> Option<&KesInitializationResult> {
        self.kes_verify_info.as_ref()
    }

    /// Returns the struct that can be passed to the delegate so that it can create the KES
    pub fn kes_init_info(&self) -> KesInitializationRecord<P> {
        let (merchant_key, customer_key) = match self.channel_info.role {
            ChannelRole::Merchant => (self.my_shards.kes_shard.clone(), self.peer_shards.kes_shard.clone()),
            ChannelRole::Customer => (self.peer_shards.kes_shard.clone(), self.my_shards.kes_shard.clone()),
        };
        KesInitializationRecord {
            kes_public_key: self.channel_info.kes_public_key.clone(),
            channel_id: self.channel_info.channel_id.name(),
            initial_balances: self.channel_info.initial_balances,
            merchant_key,
            customer_key,
        }
    }

    pub fn save_kes_verify_info(&mut self, kes_verify_info: KesInitializationResult) {
        self.kes_verify_info = Some(kes_verify_info);
    }
}