use crate::id_management::MoneroKeyManager;
use grease_p2p::{DummyDelegate, NetworkServer, OutOfBandMerchantInfo, PaymentChannel, PaymentChannels};
use libgrease::crypto::keys::Curve25519PublicKey;
use libgrease::kes::dummy_impl::DummyKes;
use libgrease::monero::dummy_impl::DummyWallet;
use libgrease::payment_channel::dummy_impl::DummyActiveChannel;
use libgrease::state_machine::{ChannelLifeCycle, NewChannelBuilder, NewChannelState};

pub type MoneroPaymentChannel = PaymentChannel<Curve25519PublicKey, DummyActiveChannel, DummyWallet>;
pub type MoneroPaymentChannels = PaymentChannels<Curve25519PublicKey, DummyActiveChannel, DummyWallet>;
pub type MoneroOutOfBandMerchantInfo = OutOfBandMerchantInfo<Curve25519PublicKey>;
pub type MoneroLifeCycle = ChannelLifeCycle<Curve25519PublicKey, DummyActiveChannel, DummyWallet>;
pub type MoneroNewState = NewChannelState<Curve25519PublicKey>;
pub type MoneroChannelBuilder = NewChannelBuilder<Curve25519PublicKey>;
pub type MoneroNetworkServer =
    NetworkServer<Curve25519PublicKey, DummyActiveChannel, DummyWallet, DummyKes, DummyDelegate, MoneroKeyManager>;
