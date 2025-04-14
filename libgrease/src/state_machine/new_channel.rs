use crate::amount::MoneroAmount;
use crate::channel_id::ChannelId;
use crate::state_machine::lifecycle::ChannelRole;
use crate::state_machine::LifecycleStage;
use digest::Digest;

/// Holds all information that needs to be collected before the merchant and client can begin the channel
/// establishment protocol. At the successful conclusion of this phase, we can emit an `OnNewChannelInfo` event with
/// all the information needed to start the channel establishment protocol.
///
/// There aren't any interaction events in this phase besides the initial call from the customer, so this phase is
/// structured around a builder pattern. Both merchant and customer get the necessary info from "somewhere". In
/// practice, it'll be a QR code or deep link, or a direct RPC call from the customer.
pub struct NewChannelState<PublicKey, SecretKey> {
    channel_role: ChannelRole,
    my_public_key: PublicKey,
    my_secret_key: SecretKey,
    my_partial_channel_id: Option<Vec<u8>>,
    peer_public_key: Option<PublicKey>,
    peer_partial_channel_id: Option<Vec<u8>>,
    amount: Option<MoneroAmount>,
}

impl<PublicKey, SecretKey> NewChannelState<PublicKey, SecretKey>
where
    PublicKey: Clone,
{
    pub fn build<D: Digest>(&self) -> Option<NewChannelInfo<PublicKey>> {
        if self.my_partial_channel_id.is_none()
            || self.peer_partial_channel_id.is_none()
            || self.amount.is_none()
            || self.peer_public_key.is_none()
        {
            return None;
        }
        let my_salt = self.my_partial_channel_id.clone().unwrap();
        let their_salt = self.peer_partial_channel_id.clone().unwrap();

        let salt = match self.channel_role {
            ChannelRole::Merchant => [my_salt, their_salt].concat(),
            ChannelRole::Customer => [their_salt, my_salt].concat(),
        };
        let channel_id = ChannelId::new::<D, _, _, _>(
            self.my_partial_channel_id.clone().unwrap(),
            self.peer_partial_channel_id.clone().unwrap(),
            salt,
            self.amount.clone().unwrap(),
        );
        Some(NewChannelInfo {
            role: self.channel_role,
            merchant_pubkey: self.my_public_key.clone(),
            customer_pubkey: self.peer_public_key.clone().unwrap(),
            amount: self.amount.clone().unwrap(),
            channel_id,
        })
    }
}

pub enum NewChannelStateCustomer {
    Initialize,
    CreatingKes,
    CreatingFundTx, // placeholder. Split into discrete steps
}

pub enum NewChannelStateMerchant {
    Initialize,
    WaitingForKes,
    CreatingFundTx, // placeholder. Split into discrete steps
}

pub struct NewChannelInfo<PublicKey> {
    role: ChannelRole,
    pub merchant_pubkey: PublicKey,
    pub customer_pubkey: PublicKey,
    /// The amount of money in the channel
    pub amount: MoneroAmount,
    /// The channel ID
    pub channel_id: ChannelId,
}

pub struct TimeoutReason {
    /// The reason for the timeout
    pub reason: String,
    /// The phase of the lifecycle when the timeout occurred
    pub stage: LifecycleStage,
}
