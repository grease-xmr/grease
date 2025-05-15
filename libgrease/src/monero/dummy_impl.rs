use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::monero::data_objects::{
    MoneroAddress, MoneroTransaction, MoneroViewKey, MultiSigInitInfo, MultiSigSeed, MultisigKeyInfo, PartialKeyImage,
    PartiallySignedMoneroTransaction, WalletBalance,
};
use crate::monero::error::MoneroWalletError;
use crate::monero::MultiSigWallet;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    fn new(_id: &ChannelId) -> Result<Self, MoneroWalletError> {
        Ok(DummyWallet { ok: true })
    }

    async fn prepare_multisig(&self) -> Result<MultiSigInitInfo, MoneroWalletError> {
        if self.ok {
            Ok(MultiSigInitInfo { init: "MultisigExampleInit".to_string() })
        } else {
            Err(MoneroWalletError::MultisigPrepare)
        }
    }

    async fn prep_make_multisig(&self, _peer_info: MultiSigInitInfo) -> Result<MultisigKeyInfo, MoneroWalletError> {
        if self.ok {
            Ok(MultisigKeyInfo { key: "MultisigExampleKey".to_string() })
        } else {
            Err(MoneroWalletError::MakeMultisig)
        }
    }

    async fn prep_import_ms_keys(&self, _info: MultisigKeyInfo) -> Result<(), MoneroWalletError> {
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
        MoneroAddress::from_str(
            "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV",
        )
        .unwrap()
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

#[cfg(test)]
mod test {
    use crate::monero::data_objects::MoneroAddress;
    use std::str::FromStr;

    #[test]
    fn valid_monero_address() {
        let address = "4Byr22j9M2878Mtyb3fEPcBNwBZf5EXqn1Yi6VzR46618SFBrYysab2Cs1474CVDbsh94AJq7vuV3Z2DRq4zLcY3LHzo1Nbv3d8J6VhvCV";
        MoneroAddress::from_str(address).unwrap();
    }
}
