use std::fmt::Display;

pub const PICONERO: u64 = 1_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MoneroAmount {
    /// The amount of money in the channel
    amount: u64,
}

impl MoneroAmount {
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
        let mut parts = xmr.split('.');
        // Parse the whole part
        let whole = parts.next()?.parse::<u64>().ok()?;
        // Parse the fractional part, if it exists
        let fraction = if let Some(frac_str) = parts.next() {
            if parts.next().is_some() {
                return None; // More than one decimal point is invalid
            }
            if frac_str.len() > 12 {
                return None; // More than 12 decimal places is invalid
            }

            // Pad the fractional part with zeros to make it 12 digits
            let mut padded_frac = frac_str.to_string();
            while padded_frac.len() < 12 {
                padded_frac.push('0');
            }

            padded_frac.parse::<u64>().ok()?
        } else {
            0
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
}

impl Display for MoneroAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.9} XMR", self.to_xmr())
    }
}

#[cfg(test)]
mod test {
    use crate::amount::MoneroAmount;

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

        let val = MoneroAmount::from_xmr("1.0001110001110");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("1.0001110001111");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("1.000.1110");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr("zero");
        assert!(val.is_none());

        let val = MoneroAmount::from_xmr(".5");
        assert!(val.is_none());
    }
}
