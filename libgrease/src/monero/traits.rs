//! Monero multi-signature wallet traits
//!
//! The traits expose the interface for the Monero multisig protocol, described in
//! [Monero's multisig design](https://docs.getmonero.org/multisignature/#moneros-multisig-design).

use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::monero::error::{MoneroWalletError, MoneroWalletServiceError};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct MoneroAddress;
pub struct MoneroViewKey;
pub struct MoneroTransaction;
pub struct TransactionId;
pub struct MultisigInitInfo;
pub struct MultisigKeyInfo;
pub struct PartialKeyImage;
pub struct PartiallySignedMoneroTransaction;
pub struct MoneroPeer;
pub struct MultiSigSeed;

#[derive(Debug, Clone, Default)]
pub struct WalletBalance {
    pub total: MoneroAmount,
    pub spendable: MoneroAmount,
    pub blocks_left: usize,
}

/// Interface for a 2-of-2 Monero multisig wallet implementation
#[allow(async_fn_in_trait)]
pub trait MultiSigWallet: Serialize + for<'de> Deserialize<'de> + Send + Sync {
    /// Preparation Step 1/3: Monero multisig wallet - generate the Multisig info string
    async fn prepare_multisig(&mut self) -> Result<MultisigInitInfo, MoneroWalletError>;
    /// Preparation Step 2/3: Consume the peer's multisig info string to initialize the wallet
    async fn make_multisig(&mut self, peer_info: MultisigInitInfo) -> Result<MultisigKeyInfo, MoneroWalletError>;
    /// Preparation Step 3/3: Import the peer's multisig keys
    async fn import_multisig_keys(&mut self, peer_info: MultisigKeyInfo) -> Result<(), MoneroWalletError>;

    /// Spending Step 1/4: Export partial key image - this needs to be done fairly soon before the transaction is
    /// broadcast, since it involves decoy selection and thus the key image is only valid for a short time.
    async fn export_multisig_key_image(&mut self) -> Result<PartialKeyImage, MoneroWalletError>;
    /// Spending Step 2/4: Import peer's partial key image - this needs to be done fairly soon before the transaction
    /// is broadcast, since it involves decoy selection and thus the key image is only valid for a short time.
    async fn import_multisig_key_image(&mut self, peer_info: PartialKeyImage) -> Result<(), MoneroWalletError>;
    /// Spending Step 3/4: Create a partially signed transaction. Only one peer should do this.
    async fn create_unsigned_tx(
        &mut self,
        to: MoneroAddress,
        amount: MoneroAmount,
    ) -> Result<PartiallySignedMoneroTransaction, MoneroWalletError>;
    /// Spending Step 4/4: Sign the transaction. Both peers need to do this.
    async fn cosign_transaction(
        &mut self,
        transaction: PartiallySignedMoneroTransaction,
    ) -> Result<MoneroTransaction, MoneroWalletError>;

    /// Return the wallet's multisig address. This is just like any other Monero address
    async fn get_address(&self) -> MoneroAddress;
    async fn get_view_key(&self) -> MoneroViewKey;
    async fn get_balance(&self) -> Result<WalletBalance, MoneroWalletError>;

    async fn get_seed(&self) -> Result<MultiSigSeed, MoneroWalletError>;
    async fn restore_from_seed(&mut self, seed: MultiSigSeed) -> Result<(), MoneroWalletError>;
}

/// Interface for a service that is able to orchestrate multi-sig transactions between wallets on the Monero network.
#[allow(async_fn_in_trait)]
pub trait MultiSigService {
    type Wallet: MultiSigWallet;

    /// Save the wallet to disk
    async fn save<P: AsRef<Path>>(&mut self, path: P) -> Result<(), MoneroWalletError>;
    /// Try and load an existing wallet from disk
    async fn load<P: AsRef<Path>>(path: P) -> Result<Self::Wallet, MoneroWalletError>;

    /// Wallet Prep 1/3: Create or load a new multisig 2-of-2 wallet. A unique wallet is required for every channel.
    async fn create_wallet(&mut self, channel_id: &ChannelId) -> Result<Self::Wallet, MoneroWalletServiceError>;
    /// Wallet Prep 2a/3: Exchange the multisig initialisation data between peers (sending)     
    async fn send_multisig_init(
        &mut self,
        wallet: &mut Self::Wallet,
        peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Wallet Prep 2b/3: Exchange the multisig initialisation data between peers (receiving)     
    async fn on_receive_multisig_init(
        &mut self,
        info: MultisigInitInfo,
        wallet: &mut Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Wallet Prep 3a/3: Exchange the multisig keys between peers (sending)
    async fn send_multisig_keys(
        &mut self,
        wallet: &mut Self::Wallet,
        peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Wallet Prep 3b/3: Exchange the multisig keys between peers (receiving)
    async fn on_receive_multisig_keys(
        &mut self,
        info: MultisigKeyInfo,
        wallet: &mut Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError>;

    /// Multisig spending 1a/3: Exchange the partial key image between peers (sending)
    async fn send_partial_key_image(
        &mut self,
        wallet: &mut Self::Wallet,
        peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Multisig spending 1b/3: Exchange the partial key image between peers (receiving)
    async fn on_receive_partial_key_image(
        &mut self,
        wallet: &mut Self::Wallet,
        info: PartialKeyImage,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Multisig spending 2a/3: Exchange unsigned transaction with peer (sending)
    async fn send_partially_signed_tx(
        &mut self,
        peer: MoneroPeer,
        wallet: &Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Multisig spending 2b/3: Exchange unsigned transaction with peer (receiving)
    async fn on_receive_partially_signed_tx(
        &mut self,
        wallet: &mut Self::Wallet,
        transaction: MoneroTransaction,
    ) -> Result<(), MoneroWalletServiceError>;
    /// Multisig spending 3/3: Exchange signed transaction with peer (sending)
    async fn broadcast_transaction(
        &mut self,
        wallet: &mut Self::Wallet,
        transaction: MoneroTransaction,
    ) -> Result<TransactionId, MoneroWalletServiceError>;

    /// Meta-function to handle all the wallet preparation steps
    async fn prepare_transaction(
        &mut self,
        wallet: &mut Self::Wallet,
        transaction: MoneroTransaction,
    ) -> Result<(), MoneroWalletServiceError>;
}
