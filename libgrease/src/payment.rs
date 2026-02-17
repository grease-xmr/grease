use crate::amount::MoneroAmount;
use monero::{Address, Network};
use monero_wallet::address::MoneroAddress;
use monero_wallet::address::Network as MoneroNetwork;

pub struct Payment {
    amount: MoneroAmount,
    address: Address,
}

impl Payment {
    /// Represent this payment as an (address, amount) tuple
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

    pub fn new<A: Into<Address>, V: Into<MoneroAmount>>(recipient: A, amount: V) -> Self {
        Self { amount: amount.into(), address: recipient.into() }
    }

    pub fn amount(&self) -> MoneroAmount {
        self.amount
    }

    pub fn recipient(&self) -> Address {
        self.address
    }
}
