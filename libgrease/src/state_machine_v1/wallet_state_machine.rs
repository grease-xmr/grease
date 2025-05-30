//! A state machine implementation to handle the creation of a Monero multisig wallet

use crate::monero::data_objects::{
    ChannelSecrets, ChannelUpdate, MoneroAddress, MultiSigInitInfo, MultisigKeyInfo, WalletInfo,
};
use crate::monero::error::MoneroWalletError;
use crate::monero::{MoneroKeyPair, MultiSigWallet};
use crate::state_machine::VssOutput;
use log::*;
use monero::Network;
use serde::{Deserialize, Serialize};

/// ```mermaid
/// stateDiagram-v2
///     [*] --> Preparation
///     Preparation --> Prepared : prepare_multisig()
///     Prepared --> MultisigMade : make_multisig(peer_data)
///     MultisigMade --> KeysExchanged : import_multisig_keys(peer_key)
///     KeysExchanged --> Complete : All steps done
///     Preparation --> Aborted : Error
///     Prepared --> Aborted : Error
///     MultisigMade --> Aborted : Error
///     KeysExchanged --> Aborted : Error
///  ```
///
/// This is a simple state machine, so we employ the implicit state pattern rather than the state-event pattern.
/// Each variant type only exposes method that allow a valid transition to the next state.

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub enum WalletState<W>
where
    W: MultiSigWallet,
{
    Preparation(WalletPreparation<W>),
    Prepared(PreSharedWallet<W>),
    MultisigMade(MadeWallet<W>),
    Ready(ReadyWallet<W>),
    Aborted(AbortedWallet<W>),
}

impl<W> WalletState<W>
where
    W: MultiSigWallet,
{
    pub fn new(network: Network, wallet: W) -> Self {
        WalletState::Preparation(WalletPreparation::new(network, wallet))
    }

    pub fn is_new(&self) -> bool {
        matches!(self, WalletState::Preparation(_))
    }
    pub fn is_prepared(&self) -> bool {
        matches!(self, WalletState::Prepared(_))
    }
    pub fn is_multisig_made(&self) -> bool {
        matches!(self, WalletState::MultisigMade(_))
    }
    pub fn is_ready(&self) -> bool {
        matches!(self, WalletState::Ready(_))
    }
    pub fn is_aborted(&self) -> bool {
        matches!(self, WalletState::Aborted(_))
    }

    pub fn to_aborted(self) -> Option<AbortedWallet<W>> {
        match self {
            WalletState::Aborted(w) => Some(w),
            _ => None,
        }
    }

    pub fn network(&self) -> Network {
        match self {
            WalletState::Preparation(w) => w.network,
            WalletState::Prepared(w) => w.network,
            WalletState::MultisigMade(w) => w.network,
            WalletState::Ready(w) => w.network,
            WalletState::Aborted(w) => w.network,
        }
    }

    pub async fn prepare_multisig(self) -> Self {
        match self {
            WalletState::Preparation(state) => state.prepare_multisig().await,
            _ => self.abort("Invalid state transition"),
        }
    }

    pub async fn make_multisig(self, peer_info: MultiSigInitInfo) -> Self {
        match self {
            WalletState::Prepared(state) => state.make_multisig(peer_info).await,
            _ => self.abort("Invalid state transition"),
        }
    }

    pub async fn import_multisig_keys(self, peer_keys: MultisigKeyInfo) -> Self {
        match self {
            WalletState::MultisigMade(state) => state.import_multisig_keys(peer_keys).await,
            _ => self.abort("Invalid state transition"),
        }
    }

    /// Save the VSS that my peer sent me, and which I can use to recover the entire wallet after a dispute resolution
    pub fn save_my_shards(self, my_shards: VssOutput) -> Self {
        match self {
            WalletState::MultisigMade(state) => state.save_my_shards(my_shards),
            _ => self.abort("Invalid state transition"),
        }
    }

    /// Save the VSS that I sent to my peer, and which he can use to recover the entire wallet after a dispute resolution
    pub fn save_peer_shards(self, peer_shards: VssOutput) -> Self {
        match self {
            WalletState::MultisigMade(state) => state.save_peer_shards(peer_shards),
            _ => self.abort("Invalid state transition"),
        }
    }

    /// Save the initial witness and proofs
    pub fn save_initial_proofs(self, secrets: ChannelSecrets, proofs: ChannelUpdate) -> Self {
        match self {
            WalletState::Ready(state) => state.save_secrets(secrets, proofs),
            _ => self.abort("Invalid state to save secrets"),
        }
    }

    /// Get the address of the wallet. If the wallet is not ready, return None.
    pub fn get_address(&self) -> Option<MoneroAddress> {
        let wallet = self.wallet();
        let network = self.network();
        self.keypair().map(|key| wallet.address_from_keypair(network, key))
    }

    pub fn init_info(&self) -> Option<&MultiSigInitInfo> {
        match self {
            WalletState::Prepared(w) => Some(w.multisig_init_info()),
            _ => None,
        }
    }

    pub fn multisig_keys(&self) -> Option<&MultisigKeyInfo> {
        match self {
            WalletState::MultisigMade(w) => Some(&w.multisigkey_info),
            WalletState::Ready(w) => Some(&w.peer_partial_key),
            _ => None,
        }
    }

    pub fn abort(self, reason: impl Into<String>) -> Self {
        let network = self.network();
        let wallet = self.to_wallet();
        Self::Aborted(AbortedWallet::other(network, wallet, reason.into()))
    }

    pub fn ready(&self) -> Option<&W> {
        match self {
            WalletState::Ready(w) => Some(&w.wallet),
            _ => None,
        }
    }

    pub fn wallet_mut(&mut self) -> &mut W {
        match self {
            WalletState::Preparation(w) => &mut w.wallet,
            WalletState::Prepared(w) => &mut w.wallet,
            WalletState::MultisigMade(w) => &mut w.wallet,
            WalletState::Ready(w) => &mut w.wallet,
            WalletState::Aborted(w) => &mut w.wallet,
        }
    }

    pub fn wallet(&self) -> &W {
        match self {
            WalletState::Preparation(w) => &w.wallet,
            WalletState::Prepared(w) => &w.wallet,
            WalletState::MultisigMade(w) => &w.wallet,
            WalletState::Ready(w) => &w.wallet,
            WalletState::Aborted(w) => &w.wallet,
        }
    }

    pub fn to_wallet(self) -> W {
        match self {
            WalletState::Preparation(w) => w.wallet,
            WalletState::Prepared(w) => w.wallet,
            WalletState::MultisigMade(w) => w.wallet,
            WalletState::Ready(w) => w.wallet,
            WalletState::Aborted(w) => w.wallet,
        }
    }

    pub fn keypair(&self) -> Option<&MoneroKeyPair> {
        match self {
            WalletState::Preparation(_) => None,
            WalletState::Prepared(p) => Some(&p.keypair),
            WalletState::MultisigMade(w) => Some(&w.keypair),
            WalletState::Ready(w) => Some(&w.keypair),
            WalletState::Aborted(_) => None,
        }
    }
}

// ------------------------------------------  Wallet Preparation   --------------------------------------------------
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct WalletPreparation<W: MultiSigWallet> {
    wallet: W,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
}

impl<W: MultiSigWallet> WalletPreparation<W> {
    fn new(network: Network, wallet: W) -> Self {
        Self { network, wallet }
    }

    pub async fn prepare_multisig(self) -> WalletState<W> {
        trace!("Wallet state machine: Prepare multisig");
        let keypair = self.wallet.generate_key_pair();
        match self.wallet.prepare_multisig().await {
            Ok(info) => WalletState::Prepared(PreSharedWallet::new(self.network, self.wallet, keypair, info)),
            Err(e) => WalletState::Aborted(AbortedWallet::new(self.network, self.wallet, e)),
        }
    }
}

// ------------------------------------------    Pre key sharing   --------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct PreSharedWallet<W: MultiSigWallet> {
    wallet: W,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_keypair",
        serialize_with = "crate::monero::helpers::serialize_keypair"
    )]
    keypair: MoneroKeyPair,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    multisig_init_info: MultiSigInitInfo,
}

impl<W: MultiSigWallet> PreSharedWallet<W> {
    fn new(network: Network, wallet: W, keypair: MoneroKeyPair, info: MultiSigInitInfo) -> Self {
        Self { network, wallet, keypair, multisig_init_info: info }
    }

    pub fn multisig_init_info(&self) -> &MultiSigInitInfo {
        &self.multisig_init_info
    }

    pub async fn make_multisig(self, peer_info: MultiSigInitInfo) -> WalletState<W> {
        trace!("Wallet state machine: Make multisig");
        match self.wallet.prep_make_multisig(peer_info).await {
            Ok(key) => WalletState::MultisigMade(MadeWallet::new(self.network, self.wallet, self.keypair, key)),
            Err(e) => WalletState::Aborted(AbortedWallet::new(self.network, self.wallet, e)),
        }
    }
}
// ---------------------------------------------  Made Wallet   -----------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct MadeWallet<W: MultiSigWallet> {
    wallet: W,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_keypair",
        serialize_with = "crate::monero::helpers::serialize_keypair"
    )]
    keypair: MoneroKeyPair,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    my_shards: Option<VssOutput>,
    peer_shards: Option<VssOutput>,
    multisigkey_info: MultisigKeyInfo,
    imported_multisigkeys: bool,
}

impl<W: MultiSigWallet> MadeWallet<W> {
    fn new(network: Network, wallet: W, keypair: MoneroKeyPair, key: MultisigKeyInfo) -> Self {
        Self {
            network,
            wallet,
            multisigkey_info: key,
            keypair,
            my_shards: None,
            peer_shards: None,
            imported_multisigkeys: false,
        }
    }

    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    pub fn save_my_shards(mut self, my_shards: VssOutput) -> WalletState<W> {
        trace!("Wallet state machine: Save my shards");
        if self.imported_multisigkeys && self.peer_shards.is_some() {
            trace!("Wallet state moving to Ready");
            WalletState::Ready(ReadyWallet::new(
                self.network,
                self.wallet,
                self.keypair,
                self.multisigkey_info,
                self.peer_shards.unwrap(),
                my_shards,
            ))
        } else {
            trace!("Saved my shards, but missing peer shards or multisig keys, so staying in MultisigMade");
            self.my_shards = Some(my_shards);
            WalletState::MultisigMade(self)
        }
    }

    pub fn save_peer_shards(mut self, peer_shards: VssOutput) -> WalletState<W> {
        trace!("Wallet state machine: Save peer shards");
        if self.imported_multisigkeys && self.my_shards.is_some() {
            WalletState::Ready(ReadyWallet::new(
                self.network,
                self.wallet,
                self.keypair,
                self.multisigkey_info,
                peer_shards,
                self.my_shards.unwrap(),
            ))
        } else {
            trace!(
                "Wallet state machine: Saving peer shards. MY shards saved: {}, keys imported: {}",
                self.my_shards.is_some(),
                self.imported_multisigkeys
            );
            self.peer_shards = Some(peer_shards);
            WalletState::MultisigMade(self)
        }
    }

    pub async fn import_multisig_keys(mut self, peer_info: MultisigKeyInfo) -> WalletState<W> {
        trace!("Wallet state machine: Import peer key");
        let import_result = self.wallet.prep_import_ms_keys(peer_info).await;
        match (import_result, self.my_shards.is_some() && self.peer_shards.is_some()) {
            (Ok(()), false) => {
                debug!(
                    "👛 Multisig partial key imported, but the wallet is not ready yet. Waiting on VSS share \
                information."
                );
                self.imported_multisigkeys = true;
                WalletState::MultisigMade(self)
            }
            (Ok(()), true) => {
                debug!("👛 Multisig wallet is Ready. All keys shared and secret shards created.");
                let my_shards = self.my_shards.expect("we've just checked that my_shards exist");
                let peer_shards = self.peer_shards.expect("we've just checked that peer_shards exist");
                WalletState::Ready(ReadyWallet::new(
                    self.network,
                    self.wallet,
                    self.keypair,
                    self.multisigkey_info,
                    peer_shards,
                    my_shards,
                ))
            }
            (Err(e), _) => WalletState::Aborted(AbortedWallet::new(self.network, self.wallet, e)),
        }
    }
}
// --------------------------------------------- Ready Wallet -----------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct ReadyWallet<W: MultiSigWallet> {
    /// The partial key of my peer. used in setting up the multisig wallet
    pub(crate) peer_partial_key: MultisigKeyInfo,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_keypair",
        serialize_with = "crate::monero::helpers::serialize_keypair"
    )]
    /// My 1-of-2 spend key for the channel wallet
    pub(crate) keypair: MoneroKeyPair,
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    pub(crate) network: Network,
    /// The encrypted secrets of *my* multisig wallet spend key
    pub(crate) peer_shards: VssOutput,
    /// The encrypted secrets of *my peer's* multisig wallet spend key
    pub(crate) my_shards: VssOutput,
    pub(crate) wallet: W,
    pub(crate) initial_secrets: Option<ChannelSecrets>,
    pub(crate) initial_proofs: Option<ChannelUpdate>,
}

impl<W: MultiSigWallet> ReadyWallet<W> {
    fn new(
        network: Network,
        wallet: W,
        keypair: MoneroKeyPair,
        peer_partial_key: MultisigKeyInfo,
        peer_shards: VssOutput,
        my_shards: VssOutput,
    ) -> Self {
        trace!("👛 Wallet state machine: New ready wallet created");
        Self {
            network,
            wallet,
            peer_partial_key,
            keypair,
            peer_shards,
            my_shards,
            initial_secrets: None,
            initial_proofs: None,
        }
    }

    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    pub fn wallet_info(&self) -> WalletInfo {
        let address = monero::Address::from_keypair(self.network, &self.keypair);
        WalletInfo {
            address,
            keypair: self.keypair,
            peer_vss_info: self.peer_shards.clone(),
            my_vss_info: self.my_shards.clone(),
        }
    }

    pub fn save_secrets(mut self, secrets: ChannelSecrets, proofs: ChannelUpdate) -> WalletState<W> {
        self.initial_secrets = Some(secrets);
        self.initial_proofs = Some(proofs);
        WalletState::Ready(self)
    }
}

// --------------------------------------------- Aborted Wallet -----------------------------------------------------
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct AbortedWallet<W: MultiSigWallet> {
    #[serde(
        deserialize_with = "crate::monero::helpers::deserialize_network",
        serialize_with = "crate::monero::helpers::serialize_network"
    )]
    network: Network,
    wallet: W,
    reason: MoneroWalletError,
}

impl<W: MultiSigWallet> AbortedWallet<W> {
    fn new(network: Network, wallet: W, reason: MoneroWalletError) -> Self {
        Self { network, wallet, reason }
    }

    fn other(network: Network, wallet: W, reason: impl Into<String>) -> Self {
        Self { network, wallet, reason: MoneroWalletError::Other(reason.into()) }
    }

    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    pub fn error(&self) -> &MoneroWalletError {
        &self.reason
    }

    pub fn reason(&self) -> String {
        self.reason.to_string()
    }
}

#[cfg(test)]
mod test {
    use crate::kes::PartialEncryptedKey;
    use crate::monero::data_objects::{MsKeyAndVssInfo, MultiSigInitInfo, MultisigKeyInfo};
    use crate::monero::dummy_impl::DummyWallet;
    use crate::monero::error::MoneroWalletError;
    use crate::state_machine::wallet_state_machine::WalletState;
    use crate::state_machine::VssOutput;
    use monero::Network;

    #[tokio::test]
    async fn test_wallet_state_machine_happy_path() {
        let wallet = DummyWallet::default();
        let mut state = WalletState::new(Network::Testnet, wallet);
        assert!(state.is_new());
        state = state.prepare_multisig().await;
        assert!(state.is_prepared());
        // ... Gets info from peer
        let info = MultiSigInitInfo { init: "MultisigTest".to_string() };
        state = state.make_multisig(info).await;
        assert!(state.is_multisig_made());
        // ... Gets key from peer
        let info = MsKeyAndVssInfo {
            multisig_key: MultisigKeyInfo { key: "MultisigKey".to_string() },
            shards_for_merchant: VssOutput {
                peer_shard: PartialEncryptedKey("PeerShardForMerchant".into()),
                kes_shard: PartialEncryptedKey("KES_shardFromCustomer".into()),
            },
        };
        // ... Calculates shards for peer
        let shards_for_customer = VssOutput {
            peer_shard: PartialEncryptedKey("PeerShardForCustomer".into()),
            kes_shard: PartialEncryptedKey("KES_shardFromMerchant".into()),
        };
        state = state.import_multisig_keys(info.multisig_key).await;
        // Save my vss shares
        state = state.save_my_shards(info.shards_for_merchant).save_peer_shards(shards_for_customer);
        assert!(state.is_ready());
    }

    #[tokio::test]
    async fn skip_prepare_multisig() {
        let wallet = DummyWallet::default();
        let mut state = WalletState::new(Network::Testnet, wallet);
        assert!(state.is_new());
        //state = state.prepare_multisig().await; <-- Skip this step
        // ... Gets info from peer
        let info = MultiSigInitInfo { init: "MultisigTest".to_string() };
        state = state.make_multisig(info).await;
        assert!(state.is_aborted());
        assert_eq!(
            state.to_aborted().unwrap().reason(),
            "Multisig wallet error: Invalid state transition"
        );
    }

    #[tokio::test]
    async fn error_in_make_multisig() {
        let wallet = DummyWallet::default();
        let mut state = WalletState::new(Network::Testnet, wallet);
        assert!(state.is_new());
        state = state.prepare_multisig().await;
        assert!(state.is_prepared());
        // ... Gets info from peer
        let info = MultiSigInitInfo { init: "MultisigTest".to_string() };
        // Simulate error
        state.wallet_mut().err();
        state = state.make_multisig(info).await;
        assert!(state.is_aborted());
        assert_eq!(state.to_aborted().unwrap().error(), &MoneroWalletError::MakeMultisig);
    }
}
