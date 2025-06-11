use crate::state_machine::lifecycle::{ChannelState, LifeCycle};
use std::any::Any;

pub trait StateStore {
    fn write_channel(&mut self, state: &ChannelState) -> Result<(), anyhow::Error>;
    fn load_channel(&self, name: &str) -> Result<ChannelState, anyhow::Error>;
}
