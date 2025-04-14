use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::state_machine::lifecycle::ChannelRole;
use crate::state_machine::new_channel::NewChannelInfo;

pub enum EstablishingChannelState {
    Initialize,
    Established,
}

pub struct Balances {
    pub merchant: MoneroAmount,
    pub customer: MoneroAmount,
}

impl EstablishingChannelState {
    pub fn new<P>(_info: NewChannelInfo<P>) -> Self {
        EstablishingChannelState::Initialize
    }

    pub fn channel_id(&self) -> &ChannelId {
        match self {
            EstablishingChannelState::Initialize => todo!("Channel ID not available in Initialize state"),
            EstablishingChannelState::Established => todo!("Channel ID not available in Established state"),
        }
    }

    pub fn role(&self) -> ChannelRole {
        match self {
            EstablishingChannelState::Initialize => todo!("Role not available in Initialize state"),
            EstablishingChannelState::Established => todo!("Role not available in Established state"),
        }
    }

    pub fn initial_balances(&self) -> Balances {
        match self {
            EstablishingChannelState::Initialize => todo!("Initial balances not available in Initialize state"),
            EstablishingChannelState::Established => todo!("Initial balances not available in Established state"),
        }
    }
}

pub struct ChannelEstablishedInfo {
    pub channel_id: ChannelId,
    pub channel_role: ChannelRole,
    pub initial_balances: Balances,
}
