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
pub struct DummyWallet {
    ok: bool,
}

impl Default for DummyWallet {
    fn default() -> Self {
        Self { ok: true }
    }
}

impl DummyWallet {
    pub fn err(&mut self) {
        self.ok = false;
    }

    pub fn clear_err(&mut self) {
        self.ok = true;
    }
}

impl MultiSigWallet for DummyWallet {
    async fn prepare_multisig(&mut self) -> Result<MultisigInitInfo, MoneroWalletError> {
        if self.ok {
            Ok(MultisigInitInfo)
        } else {
            Err(MoneroWalletError::MultisigPrepare)
        }
    }

    async fn prep_make_multisig(&mut self, _peer_info: MultisigInitInfo) -> Result<MultisigKeyInfo, MoneroWalletError> {
        if self.ok {
            Ok(MultisigKeyInfo)
        } else {
            Err(MoneroWalletError::MakeMultisig)
        }
    }

    async fn prep_import_ms_keys(&mut self, _info: MultisigKeyInfo) -> Result<(), MoneroWalletError> {
        if self.ok {
            Ok(())
        } else {
            Err(MoneroWalletError::ImportMultisigKeyImage)
        }
    }

    async fn export_key_image_for_spend(&mut self) -> Result<PartialKeyImage, MoneroWalletError> {
        if self.ok {
            Ok(PartialKeyImage)
        } else {
            Err(MoneroWalletError::ExportSpendKey)
        }
    }

    async fn import_key_image_for_spend(&mut self, _info: PartialKeyImage) -> Result<(), MoneroWalletError> {
        if self.ok {
            Ok(())
        } else {
            Err(MoneroWalletError::ImportSpendKey)
        }
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
        Ok(Self::default())
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct DummyMultiSigWalletService;

impl MultiSigService for DummyMultiSigWalletService {
    type Wallet = DummyWallet;

    async fn save<P: AsRef<Path>>(&mut self, _path: P) -> Result<(), MoneroWalletError> {
        Ok(())
    }

    async fn load<P: AsRef<Path>>(_path: P) -> Result<Self::Wallet, MoneroWalletError> {
        Ok(DummyWallet::default())
    }

    async fn create_wallet(&mut self, _channel_id: &ChannelId) -> Result<Self::Wallet, MoneroWalletServiceError> {
        Ok(DummyWallet::default())
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
