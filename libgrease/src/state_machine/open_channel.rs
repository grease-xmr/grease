use crate::channel_id::ChannelId;
use crate::state_machine::establishing_channel::{Balances, ChannelEstablishedInfo};
use crate::state_machine::lifecycle::ChannelRole;

pub struct EstablishedChannelState {
    channel_id: ChannelId,
    role: ChannelRole,
    balance: Balances,
}

impl EstablishedChannelState {
    pub fn from_new_channel_info(info: ChannelEstablishedInfo) -> Self {
        EstablishedChannelState { channel_id: info.channel_id, role: info.channel_role, balance: info.initial_balances }
    }
}
