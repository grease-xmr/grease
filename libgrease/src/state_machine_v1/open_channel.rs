//! State object for an open / established payment channel.
//!
//! There are three events that are allowed in this state:
//! - `ChannelUpdate`: This is used to update the channel state with new information. The channel remains in the `Established` state.
//! - `ChannelClose`: This indicates a co-operative close of the channel. The channel will move to the `Closing` state.
//! - `ChannelForceClose`: This indicates a force close of the channel, and will move the channel to the `Disputed` state.
//!
//! ## Updates
//!
//! ```mermaid
//! sequenceDiagram
//!         actor I as Initiator
//!         actor R as Responder
//!         I->>I: Generate proofs_i
//!         I->>R: UpdateChannel<br/>(balances_i, proofs_Ii, partial_sig_Ii, tx_i)
//!         R->>R: Verify proofs_i<br/>Generate tx_i
//!         alt verification passes
//!           R->>I: AcceptUpdate<br/>(balances_i, proofs_Ri, tx_i, partial_sig_Ri)
//!         else verification fails
//!           R->>I: UpdateFailed<br/>(reason, balance_Ri-1, proofs_Ri-1)
//!         end
//!         R->>R: Generate proofs_Ri
//!         R->>I: UpdateChannel(ProofsR)
//! ```
//!
//!
use crate::balance::Balances;
use crate::channel_metadata::ChannelMetadata;
use crate::crypto::traits::PublicKey;
use crate::monero::data_objects::{ChannelSecrets, ChannelUpdate, TransactionId};
use crate::monero::MultiSigWallet;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey + for<'d> Deserialize<'d>"))]
pub struct EstablishedChannelState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub(crate) channel_info: ChannelMetadata<P>,
    pub(crate) initial: ChannelSecrets,
    pub(crate) latest: ChannelSecrets,
    pub(crate) latest_proof: Option<ChannelUpdate>,
    pub(crate) wallet: W,
    // These are only optional because if one party has an initial balance of zero, no funding transaction is required
    // But we guarantee that at least one of them is Some
    pub(crate) merchant_funding_tx: Option<TransactionId>,
    pub(crate) customer_funding_tx: Option<TransactionId>,
}

impl<P, W> EstablishedChannelState<P, W>
where
    P: PublicKey,
    W: MultiSigWallet,
{
    pub fn current_balances(&self) -> Balances {
        self.latest.new_balances
    }
}
