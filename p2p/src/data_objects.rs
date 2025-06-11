//------------------------------------           VSS Info          ------------------------------------------------//

use libgrease::amount::MoneroAmount;
use libgrease::monero::data_objects::TransactionId;

/// Contains information needed to initialise the KES and create the VSS record.
///
/// This object contains a SECRET key and should be handled with care!
#[derive(Debug)]
pub struct ChannelInitSecrets {
    pub channel_name: String,
    /// My portion of the 2-of-2 multisig secret that needs to be split. In hexadecimal format.
    pub wallet_secret: String,
    /// The public key of the peer in hexadecimal format.
    pub peer_public_key: String,
    /// The public key of the KES in hexadecimal format. One secret shard will be encrypted to this key.
    pub kes_public_key: String,
}

impl ChannelInitSecrets {
    pub fn new(
        channel_name: String,
        wallet_secret: impl Into<String>,
        peer_public_key: impl Into<String>,
        kes_public_key: impl Into<String>,
    ) -> Self {
        ChannelInitSecrets {
            channel_name,
            wallet_secret: wallet_secret.into(),
            peer_public_key: peer_public_key.into(),
            kes_public_key: kes_public_key.into(),
        }
    }
}

#[derive(Debug)]
pub struct TransactionRecord {
    pub channel_name: String,
    pub transaction_id: TransactionId,
    pub amount: MoneroAmount,
}
