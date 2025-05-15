//! A state machine implementation to handle the creation of a Monero multisig wallet

use crate::monero::error::MoneroWalletError;
use crate::monero::traits::{MultisigInitInfo, MultisigKeyInfo};
use crate::monero::MultiSigWallet;
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
pub enum WalletState<W: MultiSigWallet> {
    Preparation(WalletPreparation<W>),
    Prepared(PreSharedWallet<W>),
    MultisigMade(MadeWallet<W>),
    Ready(ReadyWallet<W>),
    Aborted(AbortedWallet<W>),
}

impl<W: MultiSigWallet> WalletState<W> {
    pub fn new(wallet: W) -> Self {
        WalletState::Preparation(WalletPreparation::new(wallet))
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

    pub async fn prepare_multisig(self) -> Self {
        match self {
            WalletState::Preparation(state) => state.prepare_multisig().await,
            _ => self.abort("Invalid state transition"),
        }
    }

    pub async fn make_multisig(self, peer_info: MultisigInitInfo) -> Self {
        match self {
            WalletState::Prepared(state) => state.make_multisig(peer_info).await,
            _ => self.abort("Invalid state transition"),
        }
    }

    pub async fn import_multisig_keys(self, peer_info: MultisigKeyInfo) -> Self {
        match self {
            WalletState::MultisigMade(state) => state.import_multisig_keys(peer_info).await,
            _ => self.abort("Invalid state transition"),
        }
    }

    pub fn abort(self, reason: impl Into<String>) -> Self {
        let wallet = self.to_wallet();
        Self::Aborted(AbortedWallet::other(wallet, reason.into()))
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

    pub fn to_wallet(self) -> W {
        match self {
            WalletState::Preparation(w) => w.wallet,
            WalletState::Prepared(w) => w.wallet,
            WalletState::MultisigMade(w) => w.wallet,
            WalletState::Ready(w) => w.wallet,
            WalletState::Aborted(w) => w.wallet,
        }
    }
}

// ------------------------------------------  Wallet Preparation   --------------------------------------------------
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct WalletPreparation<W: MultiSigWallet> {
    wallet: W,
}

impl<W: MultiSigWallet> WalletPreparation<W> {
    fn new(wallet: W) -> Self {
        Self { wallet }
    }

    pub async fn prepare_multisig(mut self) -> WalletState<W> {
        match self.wallet.prepare_multisig().await {
            Ok(info) => WalletState::Prepared(PreSharedWallet::new(self.wallet, info)),
            Err(e) => WalletState::Aborted(AbortedWallet::new(self.wallet, e)),
        }
    }
}

// ------------------------------------------    Pre key sharing   --------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct PreSharedWallet<W: MultiSigWallet> {
    wallet: W,
    multisig_init_info: MultisigInitInfo,
}

impl<W: MultiSigWallet> PreSharedWallet<W> {
    fn new(wallet: W, info: MultisigInitInfo) -> Self {
        Self { wallet, multisig_init_info: info }
    }

    pub fn multisig_init_info(&self) -> &MultisigInitInfo {
        &self.multisig_init_info
    }

    pub async fn make_multisig(mut self, peer_info: MultisigInitInfo) -> WalletState<W> {
        match self.wallet.prep_make_multisig(peer_info).await {
            Ok(_) => WalletState::MultisigMade(MadeWallet::new(self.wallet)),
            Err(e) => WalletState::Aborted(AbortedWallet::new(self.wallet, e)),
        }
    }
}
// ---------------------------------------------  Made Wallet   -----------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct MadeWallet<W: MultiSigWallet> {
    wallet: W,
}

impl<W: MultiSigWallet> MadeWallet<W> {
    fn new(wallet: W) -> Self {
        Self { wallet }
    }

    pub fn wallet(&self) -> &W {
        &self.wallet
    }

    pub async fn import_multisig_keys(mut self, peer_info: MultisigKeyInfo) -> WalletState<W> {
        match self.wallet.prep_import_ms_keys(peer_info).await {
            Ok(_) => WalletState::Ready(ReadyWallet::new(self.wallet)),
            Err(e) => WalletState::Aborted(AbortedWallet::new(self.wallet, e)),
        }
    }
}
// --------------------------------------------- Ready Wallet -----------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct ReadyWallet<W: MultiSigWallet> {
    wallet: W,
}

impl<W: MultiSigWallet> ReadyWallet<W> {
    fn new(wallet: W) -> Self {
        Self { wallet }
    }

    pub fn wallet(&self) -> &W {
        &self.wallet
    }
}

// --------------------------------------------- Aborted Wallet -----------------------------------------------------
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "W: MultiSigWallet + for<'d> Deserialize<'d>"))]
pub struct AbortedWallet<W: MultiSigWallet> {
    wallet: W,
    reason: MoneroWalletError,
}

impl<W: MultiSigWallet> AbortedWallet<W> {
    fn new(wallet: W, reason: MoneroWalletError) -> Self {
        Self { wallet, reason }
    }

    fn other(wallet: W, reason: impl Into<String>) -> Self {
        Self { wallet, reason: MoneroWalletError::Other(reason.into()) }
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
    use crate::monero::dummy_impl::DummyWallet;
    use crate::monero::error::MoneroWalletError;
    use crate::monero::state_machine::WalletState;
    use crate::monero::traits::{MultisigInitInfo, MultisigKeyInfo};

    #[tokio::test]
    async fn test_wallet_state_machine_happy_path() {
        let wallet = DummyWallet::default();
        let mut state = WalletState::new(wallet);
        assert!(state.is_new());
        state = state.prepare_multisig().await;
        assert!(state.is_prepared());
        // ... Gets info from peer
        let info = MultisigInitInfo;
        state = state.make_multisig(info).await;
        assert!(state.is_multisig_made());
        // ... Gets key from peer
        let info = MultisigKeyInfo;
        state = state.import_multisig_keys(info).await;
        assert!(state.is_ready());
    }

    #[tokio::test]
    async fn skip_prepare_multisig() {
        let wallet = DummyWallet::default();
        let mut state = WalletState::new(wallet);
        assert!(state.is_new());
        //state = state.prepare_multisig().await; <-- Skip this step
        // ... Gets info from peer
        let info = MultisigInitInfo;
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
        let mut state = WalletState::new(wallet);
        assert!(state.is_new());
        state = state.prepare_multisig().await;
        assert!(state.is_prepared());
        // ... Gets info from peer
        let info = MultisigInitInfo;
        // Simulate error
        state.wallet_mut().err();
        state = state.make_multisig(info).await;
        assert!(state.is_aborted());
        assert_eq!(state.to_aborted().unwrap().error(), &MoneroWalletError::MakeMultisig);
    }
}
