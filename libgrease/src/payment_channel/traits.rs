use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::payment_channel::{ChannelRole, UpdateError};
use crate::state_machine::Balances;
use serde::{Deserialize, Serialize};

pub trait ChannelPayment: Sized {
    fn get_amount(&self) -> MoneroAmount;
    fn get_sender(&self) -> String;
    fn get_receiver(&self) -> String;
    fn get_sender_signature(&self) -> String;
}

pub trait ActivePaymentChannel: Serialize + for<'d> Deserialize<'d> + Send + Sync {
    type UpdateInfo: Send;
    type Finalized: ClosedPaymentChannel + Send + Sync;

    fn role(&self) -> ChannelRole;
    fn channel_id(&self) -> &ChannelId;
    fn my_balance(&self) -> MoneroAmount {
        let balances = self.balances();
        match self.role() {
            ChannelRole::Merchant => balances.merchant,
            ChannelRole::Customer => balances.customer,
        }
    }
    fn balances(&self) -> Balances;
    fn transaction_count(&self) -> usize;
    fn update(&mut self, update_info: Self::UpdateInfo) -> Result<(), UpdateError>;
    fn finalize(self) -> Self::Finalized;
}

pub trait ClosedPaymentChannel: Clone + Serialize + for<'d> Deserialize<'d> + Send {
    fn channel_id(&self) -> &ChannelId;
    fn role(&self) -> ChannelRole;
    fn final_balance(&self) -> Balances;
    fn final_transaction_count(&self) -> usize;
}
