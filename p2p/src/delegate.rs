use crate::message_types::NewChannelProposal;
use libgrease::crypto::keys::{Curve25519PublicKey, KeyError};
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::dummy_impl::DummyKes;
use libgrease::kes::KeyEscrowService;
use libgrease::monero::dummy_impl::DummyWallet;
use libgrease::monero::MultiSigWallet;
use libgrease::payment_channel::dummy_impl::DummyActiveChannel;
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::error::InvalidProposal;
use log::info;
use serde::{Deserialize, Serialize};

pub trait GreaseChannelDelegate<P, C, W, KES>: Clone + Send + Sync
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn verify_proposal(&self, data: &NewChannelProposal<P>) -> Result<(), InvalidProposal>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyDelegate;

impl GreaseChannelDelegate<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes> for DummyDelegate {
    fn verify_proposal(&self, _data: &NewChannelProposal<Curve25519PublicKey>) -> Result<(), InvalidProposal> {
        info!("Rubber stamping proposal");
        Ok(())
    }
}

pub trait KeyDelegate<P>: Clone + Send + Sync
where
    P: PublicKey,
{
    fn get_keypair(&self, index: u64) -> Result<(P::SecretKey, P), KeyError>;
    fn validate_keypair(&self, secret: &P::SecretKey, public: &P) -> bool;
}
