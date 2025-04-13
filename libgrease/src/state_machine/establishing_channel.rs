use crate::state_machine::lifecycle::ChannelRole;

pub enum EstablishingChannelState {}

pub struct ChannelEstablishedInfo {
    pub channel_id: String,
    pub channel_role: ChannelRole,
}
