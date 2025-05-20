//! Monero multi-signature wallet traits
//!
//! The traits expose the interface for the Monero multisig protocol, described in
//! [Monero's multisig design](https://docs.getmonero.org/multisignature/#moneros-multisig-design).

use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::monero::data_objects::{
    MoneroAddress, MoneroTransaction, MoneroViewKey, MultiSigInitInfo, MultiSigSeed, MultisigKeyInfo, PartialKeyImage,
    PartiallySignedMoneroTransaction, WalletBalance,
};
use crate::monero::error::MoneroWalletError;
use serde::{Deserialize, Serialize};
use std::future::Future;

pub type MoneroPrivateKey = monero::PrivateKey;
pub type MoneroKeyPair = monero::KeyPair;
pub use monero::Network;

/// Interface for a 2-of-2 Monero multisig wallet implementation
#[allow(async_fn_in_trait)]
pub trait MultiSigWallet: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Create a new wallet instance associate with the given channel ID
    fn new(channel_id: &ChannelId) -> Result<Self, MoneroWalletError>;
    /// Preparation Step 1/3: Monero multisig wallet - generate the Multisig info string
    fn prepare_multisig(&self) -> impl Future<Output = Result<MultiSigInitInfo, MoneroWalletError>> + Send;
    /// Preparation Step 2/3: Consume the peer's multisig info string to initialize the wallet
    fn prep_make_multisig(
        &self,
        peer_info: MultiSigInitInfo,
    ) -> impl Future<Output = Result<MultisigKeyInfo, MoneroWalletError>> + Send;
    /// Preparation Step 3/3: Import the peer's multisig keys
    fn prep_import_ms_keys(
        &self,
        peer_info: MultisigKeyInfo,
    ) -> impl Future<Output = Result<(), MoneroWalletError>> + Send;

    /// Spending Step 1/4: Export partial key image - this needs to be done fairly soon before the transaction is
    /// broadcast, since it involves decoy selection and thus the key image is only valid for a short time.
    fn export_key_image_for_spend(&mut self)
        -> impl Future<Output = Result<PartialKeyImage, MoneroWalletError>> + Send;
    /// Spending Step 2/4: Import peer's partial key image - this needs to be done fairly soon before the transaction
    /// is broadcast, since it involves decoy selection and thus the key image is only valid for a short time.
    fn import_key_image_for_spend(
        &mut self,
        peer_info: PartialKeyImage,
    ) -> impl Future<Output = Result<(), MoneroWalletError>> + Send;
    /// Spending Step 3/4: Create a partially signed transaction. Only one peer should do this.
    fn create_unsigned_tx(
        &mut self,
        to: MoneroAddress,
        amount: MoneroAmount,
    ) -> impl Future<Output = Result<PartiallySignedMoneroTransaction, MoneroWalletError>> + Send;
    /// Spending Step 4/4: Sign the transaction. Both peers need to do this.
    fn cosign_transaction(
        &mut self,
        transaction: PartiallySignedMoneroTransaction,
    ) -> impl Future<Output = Result<MoneroTransaction, MoneroWalletError>> + Send;

    /// Return the wallet's multisig address. This is just like any other Monero address
    fn get_address(&self) -> impl Future<Output = MoneroAddress> + Send;
    async fn get_view_key(&self) -> MoneroViewKey;
    async fn get_balance(&self) -> Result<WalletBalance, MoneroWalletError>;

    /// Generate a new key pair for the wallet. This is used for the multisig protocol.
    fn generate_key_pair(&self) -> MoneroKeyPair;

    fn address_from_keypair(&self, network: Network, keypair: &MoneroKeyPair) -> MoneroAddress {
        MoneroAddress::from_keypair(network, keypair)
    }

    async fn get_seed(&self) -> Result<MultiSigSeed, MoneroWalletError>;
    async fn restore_from_seed(seed: MultiSigSeed) -> Result<Self, MoneroWalletError>;
}
