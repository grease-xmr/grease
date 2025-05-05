use grease_p2p::{ContactInfo, ConversationIdentity};
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::MultiSigWallet;
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::{ChannelLifeCycle, ChannelSeedInfo};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct OutOfBandMerchantInfo<P>
where
    P: PublicKey,
{
    pub contact: ContactInfo,
    pub seed: ChannelSeedInfo<P>,
}

impl<P> OutOfBandMerchantInfo<P>
where
    P: PublicKey,
{
    pub fn new(contact: ContactInfo, seed: ChannelSeedInfo<P>) -> Self {
        OutOfBandMerchantInfo { contact, seed }
    }
}

/// A payments channel
///
/// A payment channel comprises
/// - the details of the peer (i.e. a way to connect to them over the internet)
/// - the current state of the Monero payment channel
///
/// Again, the word channel is overloaded
#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "P: PublicKey  + for<'d> Deserialize<'d>"))]
pub struct PaymentChannel<P, C, W, KES>
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    pub identity: ConversationIdentity,
    pub peer_info: ContactInfo,
    pub seed_info: ChannelSeedInfo<P>,
    pub state: ChannelLifeCycle<P, C, W, KES>,
}
