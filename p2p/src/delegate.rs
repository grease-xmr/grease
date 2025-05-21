use crate::errors::VssError;
use crate::message_types::NewChannelProposal;
use libgrease::crypto::keys::{Curve25519PublicKey, KeyError};
use libgrease::crypto::traits::PublicKey;
use libgrease::kes::dummy_impl::DummyKes;
use libgrease::kes::error::KesError;
use libgrease::kes::{KesInitializationRecord, KesInitializationResult, KeyEscrowService, PartialEncryptedKey};
use libgrease::monero::dummy_impl::DummyWallet;
use libgrease::monero::MultiSigWallet;
use libgrease::payment_channel::dummy_impl::DummyActiveChannel;
use libgrease::payment_channel::ActivePaymentChannel;
use libgrease::state_machine::error::InvalidProposal;
use libgrease::state_machine::{ChannelInitSecrets, VssOutput};
use log::info;
use serde::{Deserialize, Serialize};
use std::future::Future;

pub trait GreaseChannelDelegate<P, C, W, KES>: Clone + Send + Sync
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn verify_proposal(&self, data: &NewChannelProposal<P>) -> Result<(), InvalidProposal>;

    /// Given a secret and the public key for the KES and peer, split and encrypt the secret using a suitable scheme.
    fn create_vss(&self, info: ChannelInitSecrets<P>) -> impl Future<Output = Result<VssOutput, VssError>> + Send;

    fn with_kes(&self) -> Result<&KES, KesError>;

    fn initialize_kes(
        &self,
        init: KesInitializationRecord<P>,
    ) -> impl Future<Output = Result<KesInitializationResult, KesError>> + Send {
        async move {
            let kes = self.with_kes()?;
            kes.initialize(init).await
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DummyDelegate {
    kes: DummyKes,
}

impl GreaseChannelDelegate<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes> for DummyDelegate {
    fn verify_proposal(&self, _data: &NewChannelProposal<Curve25519PublicKey>) -> Result<(), InvalidProposal> {
        info!("Rubber stamping proposal");
        Ok(())
    }

    fn create_vss(
        &self,
        _info: ChannelInitSecrets<Curve25519PublicKey>,
    ) -> impl Future<Output = Result<VssOutput, VssError>> + Send {
        async {
            info!("Creating VSS");
            let result = VssOutput {
                peer_shard: PartialEncryptedKey("DemoEncryptedKey".to_string()),
                kes_shard: PartialEncryptedKey("DemoEncryptedKey".to_string()),
            };
            Ok(result)
        }
    }

    fn with_kes(&self) -> Result<&DummyKes, KesError> {
        Ok(&self.kes)
    }
}

pub trait KeyDelegate<P>: Clone + Send + Sync
where
    P: PublicKey,
{
    fn get_keypair(&self, index: u64) -> Result<(P::SecretKey, P), KeyError>;
    fn validate_keypair(&self, secret: &P::SecretKey, public: &P) -> bool;
}
