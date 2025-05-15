use crate::channel_id::ChannelId;
use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigService;
use crate::payment_channel::{ActivePaymentChannel, ChannelRole};
use crate::state_machine::establishing_channel::ChannelEstablishedInfo;
use crate::state_machine::traits::ChannelState;
use log::debug;
use serde::{Deserialize, Serialize};

pub struct ChannelUpdateInfo<C>
where
    C: ActivePaymentChannel,
{
    channel_name: String,
    update: C::UpdateInfo,
}

impl<C> ChannelUpdateInfo<C>
where
    C: ActivePaymentChannel,
{
    pub fn new(channel_name: String, update: C::UpdateInfo) -> Self {
        ChannelUpdateInfo { channel_name, update }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: ActivePaymentChannel + for<'d> Deserialize<'d>"))]
pub struct EstablishedChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    pub(crate) secret: P::SecretKey,
    pub(crate) payment_channel: C,
    pub(crate) wallet: WS::Wallet,
    pub(crate) wallet_service: WS,
    pub(crate) kes: KES,
}

impl<P, C, WS, KES> EstablishedChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    pub fn from_new_channel_info(info: ChannelEstablishedInfo<C, WS, KES>, secret: P::SecretKey) -> Self {
        EstablishedChannelState {
            secret,
            payment_channel: info.channel,
            wallet: info.wallet,
            wallet_service: info.wallet_service,
            kes: info.kes,
        }
    }

    /// Updates the channel state from the given update information.
    ///
    /// This function is responsible for
    /// - (Trying to) Updating the channel state with the new information
    /// - Informing relevant parties about result of the update.
    pub fn try_update(&mut self, update: ChannelUpdateInfo<C>) -> UpdateResult {
        // Update the channel state with the new information
        // This is a placeholder for the actual update logic
        let update_record = update.update;
        match self.payment_channel.update(update_record) {
            Ok(_) => {
                // Successfully updated the channel state
                // Inform relevant parties about the success
                debug!("Channel state updated successfully.");
                UpdateResult::Success
            }
            Err(e) => {
                // Failed to update the channel state
                // Inform relevant parties about the failure
                debug!("Failed to update channel state: {:?}", e);
                UpdateResult::Failure
            }
        }
    }
}

impl<P, C, WS, KES> ChannelState for EstablishedChannelState<P, C, WS, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    WS: MultiSigService,
    KES: KeyEscrowService,
{
    fn channel_id(&self) -> &ChannelId {
        self.payment_channel.channel_id()
    }

    fn role(&self) -> ChannelRole {
        self.payment_channel.role()
    }
}

pub enum UpdateResult {
    Success,
    Failure,
}
