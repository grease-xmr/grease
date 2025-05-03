use crate::channel_id::ChannelId;
use crate::payment_channel::traits::ActivePaymentChannel;
use crate::payment_channel::{ChannelRole, ClosedPaymentChannel, UpdateError};
use crate::state_machine::Balances;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyActiveChannel {
    channel_id: ChannelId,
    role: ChannelRole,
    tx_count: usize,
    balances: Balances,
}

impl DummyActiveChannel {
    pub fn new(channel_id: ChannelId, role: ChannelRole, balances: Balances) -> Self {
        DummyActiveChannel { channel_id, role, tx_count: 0, balances }
    }
}

impl ActivePaymentChannel for DummyActiveChannel {
    type UpdateInfo = DummyUpdateInfo;
    type Finalized = DummyClosedChannel;

    fn role(&self) -> ChannelRole {
        self.role
    }

    fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    fn balances(&self) -> Balances {
        self.balances
    }

    fn transaction_count(&self) -> usize {
        self.tx_count
    }

    fn update(&mut self, info: DummyUpdateInfo) -> Result<(), UpdateError> {
        let original = self.balances.total();
        let new = info.new_balance.total();
        if original != new {
            return Err(UpdateError::NotBalanced);
        }
        self.balances = info.new_balance;
        self.tx_count += 1;
        Ok(())
    }

    fn finalize(self) -> Self::Finalized {
        DummyClosedChannel {
            channel_id: self.channel_id,
            role: self.role,
            tx_count: self.tx_count,
            balances: self.balances,
        }
    }
}

pub struct DummyUpdateInfo {
    pub new_balance: Balances,
}

#[derive(Serialize, Deserialize)]
pub struct DummyClosedChannel {
    channel_id: ChannelId,
    role: ChannelRole,
    tx_count: usize,
    balances: Balances,
}

impl ClosedPaymentChannel for DummyClosedChannel {
    fn channel_id(&self) -> &ChannelId {
        &self.channel_id
    }

    fn role(&self) -> ChannelRole {
        self.role
    }

    fn final_balance(&self) -> Balances {
        self.balances
    }

    fn final_transaction_count(&self) -> usize {
        self.tx_count
    }
}
