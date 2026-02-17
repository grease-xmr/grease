use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::iter::Sum;
use std::ops::{Add, AddAssign, Neg, SubAssign};

pub const PICONERO: u64 = 1_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MoneroAmount {
    /// The amount of money in the channel
    amount: u64,
}

impl MoneroAmount {
    /// Returns true if the amount is zero.
    pub fn is_zero(&self) -> bool {
        self.amount == 0
    }

    /// Creates a new `MoneroAmount` from a value in piconero.
    pub fn from_piconero(amount: u64) -> Self {
        MoneroAmount { amount }
    }

    /// Converts the `MoneroAmount` to piconero.
    pub fn to_piconero(&self) -> u64 {
        self.amount
    }

    /// Creates a new `MoneroAmount` from a string representing whole XMR units.
    /// Returns `None` if the string is not a valid number representation.
    pub fn from_xmr(xmr: &str) -> Option<Self> {
        if xmr.is_empty() {
            return None;
        }
        let (whole, frac_str) = match xmr.strip_prefix(".") {
            Some(frac) => ("0", frac),
            None => {
                let mut parts = xmr.split('.');
                let whole = parts.next()?;
                let fraction = parts.next().unwrap_or("0");
                if parts.next().is_some() {
                    return None; // More than one decimal point is invalid
                }
                (whole, fraction)
            }
        };
        if frac_str.len() > 12 {
            return None; // More than 12 decimal places is invalid
        }
        // Parse the whole part
        let whole = whole.parse::<u64>().ok()?;
        // Parse the fractional part, if it exists
        let fraction = {
            // Pad the fractional part with zeros to make it 12 digits
            let mut padded_frac = frac_str.to_string();
            while padded_frac.len() < 12 {
                padded_frac.push('0');
            }
            padded_frac.parse::<u64>().ok()?
        };

        // Calculate the total amount in piconero
        let amount = whole.checked_mul(PICONERO)?.checked_add(fraction)?;

        Some(MoneroAmount { amount })
    }

    /// Converts the `MoneroAmount` to whole XMR units as a floating-point value.
    pub fn to_xmr(&self) -> f64 {
        self.amount as f64 / PICONERO as f64
    }

    /// Converts the `MoneroAmount` to whole XMR units as a tuple of (whole, fraction).
    pub fn to_xmr_u64(&self) -> (u64, u64) {
        let whole = self.amount / PICONERO;
        let fraction = self.amount % PICONERO;
        (whole, fraction)
    }

    pub fn checked_apply_delta(&self, delta: MoneroDelta) -> Option<Self> {
        if delta.amount < 0 && self.amount >= delta.amount.unsigned_abs() {
            Some(MoneroAmount { amount: self.amount - delta.amount.unsigned_abs() })
        } else if delta.amount >= 0 {
            delta.amount.cast_unsigned().checked_add(self.amount).map(MoneroAmount::from_piconero)
        } else {
            None // No change or invalid operation
        }
    }
}

impl PartialOrd for MoneroAmount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Add for MoneroAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        MoneroAmount { amount: self.amount.saturating_add(other.amount) }
    }
}

impl AddAssign for MoneroAmount {
    fn add_assign(&mut self, other: Self) {
        self.amount = self.amount.saturating_add(other.amount);
    }
}

impl SubAssign for MoneroAmount {
    fn sub_assign(&mut self, other: Self) {
        self.amount = self.amount.saturating_sub(other.amount);
    }
}

impl Sum for MoneroAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(MoneroAmount::default(), |acc, x| {
            let total = acc.amount.checked_add(x.amount).expect("MoneroAmount overflow");
            MoneroAmount { amount: total }
        })
    }
}

impl Ord for MoneroAmount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.amount.cmp(&other.amount)
    }
}

impl Display for MoneroAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.9} XMR", self.to_xmr())
    }
}

/// Converts a u64 into piconero.
impl From<u64> for MoneroAmount {
    fn from(amount: u64) -> Self {
        MoneroAmount::from_piconero(amount)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MoneroDelta {
    /// The amount of money in the channel
    pub amount: i64,
}

impl From<i64> for MoneroDelta {
    fn from(amount: i64) -> Self {
        MoneroDelta { amount }
    }
}

impl From<MoneroAmount> for MoneroDelta {
    fn from(amount: MoneroAmount) -> Self {
        MoneroDelta { amount: amount.to_piconero() as i64 }
    }
}

impl Neg for MoneroDelta {
    type Output = MoneroDelta;

    fn neg(self) -> Self::Output {
        MoneroDelta { amount: -self.amount }
    }
}

#[cfg(test)]
mod test {
    use crate::amount::{MoneroAmount, MoneroDelta};

    #[test]
    fn from_xmr_strings() {
        let val = MoneroAmount::from_xmr("1.0").unwrap();
        assert_eq!(val.to_piconero(), 1_000_000_000_000);

        let val = MoneroAmount::from_xmr("1.25").unwrap();
        assert_eq!(val.to_piconero(), 1_250_000_000_000);

        let val = MoneroAmount::from_xmr("10.0025024124").unwrap();
        assert_eq!(val.to_piconero(), 10_002_502_412_400);

        let val = MoneroAmount::from_xmr("0.12345").unwrap();
        assert_eq!(val.to_piconero(), 123_450_000_000);

        let val = MoneroAmount::from_xmr("123").unwrap();
        assert_eq!(val.to_piconero(), 123_000_000_000_000);

        let val = MoneroAmount::from_xmr(".5").unwrap();
        assert_eq!(val.to_piconero(), 500_000_000_000);

        let val = MoneroAmount::from_xmr("1.0001110001110");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr(".0001110001110");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("1.0001110001111");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("1.000.1110");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("zero");
        assert!(val.is_none());
    }

    #[test]
    fn test_is_zero() {
        assert!(MoneroAmount::default().is_zero());
        assert!(!MoneroAmount::from_piconero(1).is_zero());
    }

    #[test]
    fn test_from_piconero() {
        let amount = MoneroAmount::from_piconero(1_000_000_000_000);
        assert_eq!(amount.to_piconero(), 1_000_000_000_000);
    }

    #[test]
    fn test_to_xmr() {
        let amount = MoneroAmount::from_piconero(1_250_000_000_000);
        assert_eq!(amount.to_xmr(), 1.25);
    }

    #[test]
    fn test_to_xmr_u64() {
        let amount = MoneroAmount::from_piconero(1_250_000_000_000);
        assert_eq!(amount.to_xmr_u64(), (1, 250_000_000_000));
    }

    #[test]
    fn test_from_xmr_valid() {
        let amount = MoneroAmount::from_xmr("1.25").unwrap();
        assert_eq!(amount.to_piconero(), 1_250_000_000_000);
        let amount = MoneroAmount::from_xmr(".1234").unwrap();
        assert_eq!(amount.to_piconero(), 123_400_000_000);
        let amount = MoneroAmount::from_xmr(".001002").unwrap();
        assert_eq!(amount.to_piconero(), 1_002_000_000);
    }

    #[test]
    fn test_from_xmr_invalid() {
        assert!(MoneroAmount::from_xmr("1.0001110001110").is_none());
        assert!(MoneroAmount::from_xmr("1.000.1110").is_none());
        assert!(MoneroAmount::from_xmr("zero").is_none());
    }

    #[test]
    fn test_checked_apply_delta_positive() {
        let amount = MoneroAmount::from_piconero(1_000_000_000_000);
        let delta = MoneroDelta::from(500_000_000_000);
        let new_amount = amount.checked_apply_delta(delta).unwrap();
        assert_eq!(new_amount.to_piconero(), 1_500_000_000_000);
    }

    #[test]
    fn test_checked_apply_delta_negative() {
        let amount = MoneroAmount::from_piconero(1_000_000_000_000);
        let delta = MoneroDelta::from(-500_000_000_000);
        let new_amount = amount.checked_apply_delta(delta).unwrap();
        assert_eq!(new_amount.to_piconero(), 500_000_000_000);
    }

    #[test]
    fn test_checked_apply_delta_invalid() {
        let amount = MoneroAmount::from_piconero(500_000_000_000);
        let delta = MoneroDelta::from(-1_000_000_000_000);
        assert!(amount.checked_apply_delta(delta).is_none());
    }

    #[test]
    fn test_add_trait() {
        let amount1 = MoneroAmount::from_piconero(1_000_000_000_000);
        let amount2 = MoneroAmount::from_piconero(500_000_000_000);
        let result = amount1 + amount2;
        assert_eq!(result.to_piconero(), 1_500_000_000_000);
    }

    #[test]
    fn test_add_assign_trait() {
        let mut amount = MoneroAmount::from_piconero(1_000_000_000_000);
        let delta = MoneroAmount::from_piconero(500_000_000_000);
        amount += delta;
        assert_eq!(amount.to_piconero(), 1_500_000_000_000);
    }

    #[test]
    fn test_sub_assign_trait() {
        let mut amount = MoneroAmount::from_piconero(1_000_000_000_000);
        let delta = MoneroAmount::from_piconero(500_000_000_000);
        amount -= delta;
        assert_eq!(amount.to_piconero(), 500_000_000_000);
    }

    #[test]
    fn test_sum_trait() {
        let amounts = vec![
            MoneroAmount::from_piconero(1_000_000_000_000),
            MoneroAmount::from_piconero(500_000_000_000),
            MoneroAmount::from_piconero(250_000_000_000),
        ];
        let total: MoneroAmount = amounts.into_iter().sum();
        assert_eq!(total.to_piconero(), 1_750_000_000_000);
    }

    #[test]
    fn test_partial_ord_trait() {
        let amount1 = MoneroAmount::from_piconero(1_000_000_000_000);
        let amount2 = MoneroAmount::from_piconero(500_000_000_000);
        assert!(amount1 > amount2);
        assert!(amount2 < amount1);
    }

    #[test]
    fn test_ord_trait() {
        let amount1 = MoneroAmount::from_piconero(1_000_000_000_000);
        let amount2 = MoneroAmount::from_piconero(500_000_000_000);
        assert_eq!(amount1.cmp(&amount2), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_display_trait() {
        let amount = MoneroAmount::from_piconero(1_250_000_000_000);
        assert_eq!(format!("{}", amount), "1.250000000 XMR");
    }

    #[test]
    fn test_neg_trait_for_delta() {
        let delta = MoneroDelta::from(500_000_000_000);
        let neg_delta = -delta;
        assert_eq!(neg_delta.amount, -500_000_000_000);
    }
}
