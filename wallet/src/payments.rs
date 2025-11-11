use crate::MoneroAddress;
use libgrease::amount::MoneroAmount;
use libgrease::grease_protocol::multisig_wallet::MoneroPayment;
use monero::{Address, Network};
use monero_wallet::address::Network as MoneroNetwork;

pub struct Payment {
    amount: MoneroAmount,
    address: Address,
}

impl Payment {
    /// Rep[resent this payment as an (address, amount) tuple
    pub fn as_tuple(&self) -> (MoneroAddress, u64) {
        let a = &self.address.to_string();
        let network = match self.address.network {
            Network::Mainnet => MoneroNetwork::Mainnet,
            Network::Stagenet => MoneroNetwork::Stagenet,
            Network::Testnet => MoneroNetwork::Testnet,
        };
        let address = MoneroAddress::from_str(network, a.as_str()).expect("valid address to map to MoneroAddress");
        (address, self.amount.to_piconero())
    }
}

impl MoneroPayment for Payment {
    fn new<A: Into<Address>, V: Into<MoneroAmount>>(recipients: A, amount: V) -> Self {
        Self { amount: amount.into(), address: recipients.into() }
    }

    fn amount(&self) -> MoneroAmount {
        self.amount
    }

    fn recipient(&self) -> Address {
        self.address
    }
}
