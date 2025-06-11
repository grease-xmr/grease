use crate::amount::{MoneroAmount, MoneroDelta};
use serde::{Deserialize, Serialize};

//------------------------------------           Balances          ------------------------------------------------//
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balances {
    pub merchant: MoneroAmount,
    pub customer: MoneroAmount,
}

impl Balances {
    pub fn new(merchant: MoneroAmount, customer: MoneroAmount) -> Self {
        Balances { merchant, customer }
    }

    pub fn total(&self) -> MoneroAmount {
        self.merchant + self.customer
    }

    pub fn pay(&self, amount: MoneroAmount) -> Option<Self> {
        let delta = MoneroDelta::from(amount);
        self.apply_delta(delta)
    }

    pub fn refund(&self, amount: MoneroAmount) -> Option<Self> {
        let delta = MoneroDelta::from(amount);
        self.apply_delta(-delta)
    }

    pub fn apply_delta(&self, delta: MoneroDelta) -> Option<Self> {
        let merchant = self.merchant.checked_apply_delta(delta)?;
        let customer = self.customer.checked_apply_delta(-delta)?;
        Some(Balances::new(merchant, customer))
    }
}

#[cfg(test)]
mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};
    use crate::balance::Balances;

    fn default_balances() -> Balances {
        Balances::new(MoneroAmount::from_xmr("1.0").unwrap(), MoneroAmount::from_xmr("2.0").unwrap())
    }

    #[test]
    fn test_apply_delta_success() {
        let balances = default_balances();
        let delta = MoneroDelta::from(MoneroAmount::from_xmr("0.5").unwrap());
        let updated_balances = balances.apply_delta(delta).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("1.5").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("1.5").unwrap());
    }

    #[test]
    fn test_apply_delta_overflow() {
        let balances = default_balances();
        let delta = MoneroDelta::from(MoneroAmount::from_xmr("3").unwrap());
        assert!(balances.apply_delta(delta).is_none());
    }

    #[test]
    fn test_apply_delta_negative_delta() {
        let balances = default_balances();
        let delta = -MoneroDelta::from(MoneroAmount::from_xmr("0.5").unwrap());
        let updated_balances = balances.apply_delta(delta).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("0.5").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("2.5").unwrap());
    }

    #[test]
    fn test_pay_success() {
        let balances = default_balances();
        let updated_balances = balances.pay(MoneroAmount::from_xmr("0.5").unwrap()).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("1.5").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("1.5").unwrap());
    }

    #[test]
    fn test_pay_insufficient_balance() {
        let balances = default_balances();
        assert!(balances.pay(MoneroAmount::from_xmr("3.0").unwrap()).is_none());
    }

    #[test]
    fn test_pay_zero_amount() {
        let balances = default_balances();
        let updated_balances = balances.pay(MoneroAmount::from_xmr("0.0").unwrap()).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("1.0").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("2.0").unwrap());
    }

    #[test]
    fn test_refund_success() {
        let balances = default_balances();
        let updated_balances = balances.refund(MoneroAmount::from_xmr("0.5").unwrap()).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("0.5").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("2.5").unwrap());
    }

    #[test]
    fn test_refund_insufficient_balance() {
        let balances = default_balances();
        assert!(balances.refund(MoneroAmount::from_xmr("3.0").unwrap()).is_none());
    }

    #[test]
    fn test_refund_zero_amount() {
        let balances = default_balances();
        let updated_balances = balances.refund(MoneroAmount::from_xmr("0.0").unwrap()).unwrap();

        assert_eq!(updated_balances.merchant, MoneroAmount::from_xmr("1.0").unwrap());
        assert_eq!(updated_balances.customer, MoneroAmount::from_xmr("2.0").unwrap());
    }
}
