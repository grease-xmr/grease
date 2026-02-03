use crate::balance::Balances;
use crate::channel_metadata::StaticChannelMetadata;
use crate::cryptography::dleq::Dleq;
use crate::state_machine::proposing_channel::RejectProposalReason;
use crate::state_machine::timeouts::TimeoutReason;
use ciphersuite::Ed25519;
use grease_grumpkin::Grumpkin;
use modular_frost::curve::Curve;
use monero::Network;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedChannelState<SF = Grumpkin, KC = Ed25519>
where
    KC: Curve,
    SF: Curve,
    Ed25519: Dleq<KC> + Dleq<SF>,
{
    reason: ChannelClosedReason,
    #[serde(bound = "")]
    metadata: StaticChannelMetadata<KC>,
    final_balances: Balances,
    _sf: std::marker::PhantomData<SF>,
}

impl<SF, KC> ClosedChannelState<SF, KC>
where
    KC: Curve,
    SF: Curve,
    Ed25519: Dleq<KC> + Dleq<SF>,
{
    /// Create a new closed channel state
    pub fn new(reason: ChannelClosedReason, metadata: StaticChannelMetadata<KC>, final_balances: Balances) -> Self {
        ClosedChannelState { reason, metadata, final_balances, _sf: std::marker::PhantomData }
    }

    pub fn to_channel_state(self) -> ChannelState<SF, KC> {
        ChannelState::Closed(self)
    }

    pub fn multisig_address(&self, _network: Network) -> Option<String> {
        None
    }

    /// Get the reason for the channel being closed
    pub fn reason(&self) -> &ChannelClosedReason {
        &self.reason
    }

    pub fn final_balances(&self) -> Balances {
        self.final_balances
    }
}

use crate::state_machine::lifecycle::{ChannelState, LifeCycle, LifecycleStage};

impl<SF, KC> LifeCycle<KC> for ClosedChannelState<SF, KC>
where
    KC: Curve,
    SF: Curve,
    Ed25519: Dleq<KC> + Dleq<SF>,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Closed
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        &self.metadata
    }

    fn balance(&self) -> Balances {
        self.final_balances
    }

    fn wallet_address(&self, network: Network) -> Option<String> {
        self.multisig_address(network)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChannelClosedReason {
    /// The channel was closed normally (cooperative close)
    Normal,
    /// The channel was closed due to a timeout
    Timeout(TimeoutReason),
    /// The channel was force closed via KES after dispute window passed
    ForceClosed,
    /// The channel was closed following a successful dispute (defender proved newer state)
    Disputed,
    /// The channel was never opened because the terms were rejected
    Rejected(RejectProposalReason),
}

impl PartialEq for ChannelClosedReason {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (ChannelClosedReason::Normal, ChannelClosedReason::Normal)
                | (ChannelClosedReason::Timeout(_), ChannelClosedReason::Timeout(_))
                | (ChannelClosedReason::ForceClosed, ChannelClosedReason::ForceClosed)
                | (ChannelClosedReason::Disputed, ChannelClosedReason::Disputed)
                | (ChannelClosedReason::Rejected(_), ChannelClosedReason::Rejected(_))
        )
    }
}

impl Eq for ChannelClosedReason {}
