use crate::amount::MoneroAmount;
use crate::state_machine::Balances;

#[derive(Debug, Clone, Copy)]
pub enum ChannelUpdateStatus {
    /// The update was accepted by the peer successfully.
    Success,
    /// The peer rejected the update due to insufficient funds in the channel.
    InsufficientFunds,
    /// The peer rejected the update due to an invalid signature.
    InvalidSignature,
}

pub struct PaymentResponse {
    /// The status of the payment update.
    pub status: ChannelUpdateStatus,
    /// The amount of money that was sent in the payment.
    pub amount: MoneroAmount,
    /// The new balances of the channel after the payment.
    pub new_balances: Balances,
    /// The signature of the merchant for the payment.
    pub merchant_signature: String,
    /// The signature of the customer for the payment.
    pub customer_signature: String,
}

impl PaymentResponse {
    pub fn get_status(&self) -> ChannelUpdateStatus {
        self.status
    }

    pub fn get_amount(&self) -> MoneroAmount {
        self.amount
    }

    pub fn get_new_balances(&self) -> Balances {
        self.new_balances
    }
    pub fn get_merchant_signature(&self) -> &str {
        &self.merchant_signature
    }

    pub fn get_customer_signature(&self) -> &str {
        &self.customer_signature
    }
}
