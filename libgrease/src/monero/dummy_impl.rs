use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::monero::error::{MoneroWalletError, MoneroWalletServiceError};
use crate::monero::traits::{
    MoneroAddress, MoneroPeer, MoneroTransaction, MoneroViewKey, MultiSigSeed, MultiSigService, MultisigInitInfo,
    MultisigKeyInfo, PartialKeyImage, PartiallySignedMoneroTransaction, TransactionId, WalletBalance,
};
use crate::monero::MultiSigWallet;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyWallet;

impl MultiSigWallet for DummyWallet {
    async fn prepare_multisig(&mut self) -> Result<MultisigInitInfo, MoneroWalletError> {
        Ok(MultisigInitInfo)
    }

    async fn make_multisig(&mut self, _peer_info: MultisigInitInfo) -> Result<MultisigKeyInfo, MoneroWalletError> {
        Ok(MultisigKeyInfo)
    }

    async fn import_multisig_keys(&mut self, _info: MultisigKeyInfo) -> Result<(), MoneroWalletError> {
        Ok(())
    }

    async fn export_multisig_key_image(&mut self) -> Result<PartialKeyImage, MoneroWalletError> {
        Ok(PartialKeyImage)
    }

    async fn import_multisig_key_image(&mut self, _info: PartialKeyImage) -> Result<(), MoneroWalletError> {
        Ok(())
    }

    async fn create_unsigned_tx(
        &mut self,
        _to: MoneroAddress,
        _amount: MoneroAmount,
    ) -> Result<PartiallySignedMoneroTransaction, MoneroWalletError> {
        Ok(PartiallySignedMoneroTransaction)
    }

    async fn cosign_transaction(
        &mut self,
        _tx: PartiallySignedMoneroTransaction,
    ) -> Result<MoneroTransaction, MoneroWalletError> {
        Ok(MoneroTransaction)
    }

    async fn get_address(&self) -> MoneroAddress {
        MoneroAddress
    }

    async fn get_view_key(&self) -> MoneroViewKey {
        MoneroViewKey
    }

    async fn get_balance(&self) -> Result<WalletBalance, MoneroWalletError> {
        Ok(WalletBalance::default())
    }

    async fn get_seed(&self) -> Result<MultiSigSeed, MoneroWalletError> {
        Ok(MultiSigSeed)
    }

    async fn restore_from_seed(_seed: MultiSigSeed) -> Result<Self, MoneroWalletError> {
        Ok(Self)
    }
}

pub struct DummyMultiSigWalletService;

impl MultiSigService for DummyMultiSigWalletService {
    type Wallet = DummyWallet;

    async fn save<P: AsRef<Path>>(&mut self, _path: P) -> Result<(), MoneroWalletError> {
        Ok(())
    }

    async fn load<P: AsRef<Path>>(_path: P) -> Result<Self::Wallet, MoneroWalletError> {
        Ok(DummyWallet)
    }

    async fn create_wallet(&mut self, _channel_id: &ChannelId) -> Result<Self::Wallet, MoneroWalletServiceError> {
        Ok(DummyWallet)
    }

    async fn send_multisig_init(
        &mut self,
        _wallet: &mut Self::Wallet,
        _peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn on_receive_multisig_init(
        &mut self,
        _info: MultisigInitInfo,
        _wallet: &mut Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn send_multisig_keys(
        &mut self,
        _wallet: &mut Self::Wallet,
        _peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn on_receive_multisig_keys(
        &mut self,
        _info: MultisigKeyInfo,
        _wallet: &mut Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn send_partial_key_image(
        &mut self,
        _wallet: &mut Self::Wallet,
        _peer: MoneroPeer,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn on_receive_partial_key_image(
        &mut self,
        _wallet: &mut Self::Wallet,
        _info: PartialKeyImage,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn send_partially_signed_tx(
        &mut self,
        _peer: MoneroPeer,
        _wallet: &Self::Wallet,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn on_receive_partially_signed_tx(
        &mut self,
        _wallet: &mut Self::Wallet,
        _tx: MoneroTransaction,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }

    async fn broadcast_transaction(
        &mut self,
        _wallet: &mut Self::Wallet,
        _tx: MoneroTransaction,
    ) -> Result<TransactionId, MoneroWalletServiceError> {
        Ok(TransactionId)
    }

    async fn prepare_transaction(
        &mut self,
        _wallet: &mut Self::Wallet,
        _tx: MoneroTransaction,
    ) -> Result<(), MoneroWalletServiceError> {
        Ok(())
    }
}
