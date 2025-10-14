use std::fmt::Display;
use ark_ff::Field;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;


pub struct FieldElement<F: Field>(pub F);

impl<F: Field> FieldElement<F> {
    /// Convert a hex string in big-endian order to a field element, if possible.
    /// The hex string may optionally start with "0x".
    /// The hex string must have an even length, as it represents full bytes and is expected to be in big-endian order.
    pub fn from_hex(value: &str) -> Result<Self, String> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        if !value.len().is_multiple_of(2) {
            return Err(format!("hex length must be even for full byte encoding: {}", value));
        }
        let buf = hex::decode(value).map_err(|_| format!("could not decode hex: {}", value))?;
        let radix = F::from(256);
        let mut res = F::ZERO;

        // assume the hex is always in big-endian order
        for d in buf.iter() {
            res *= &radix;
            res += &F::from(*d as u64);
        }
        Ok(Self(res))
    }

    /// Convert a field element to a hex string in big-endian order
    pub fn to_hex(&self) -> String {
        // let repr = self.to_repr();
        // let reversed = repr.as_ref().iter().rev().cloned().collect::<Vec<u8>>();
        // hex::encode(&reversed)
    }
}

// impl Display for FieldElement {
//     /// Returns a hex string representation of the field element of the form "Fr(0x00000....)".
//     /// The hex string is zero-padded to 64 characters and always represented in big-endian format.
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "Fr(0x{})", self.to_hex())
//     }
// }

#[cfg(test)]
mod test {
    use crate::ff::FieldElement;
    use ff::{Field, PrimeField};

    #[test]
    fn test_ff() {
        let a = FieldElement::from(2);
        assert_eq!("0000000000000000000000000000000000000000000000000000000000000002", a.to_hex());

        let b: FieldElement =
            FieldElement::from_str_vartime("21888242871839275222246405745257275088548364400416034343698204186575808495619")
                .unwrap();
        assert_eq!("0000000000000000000000000000000000000000000000000000000000000002", b.to_hex());
        assert_eq!(&a, &b);
    }

    #[test]
    fn encoding() {
        let a = FieldElement::from_hex("0x12340000abcdef000055550066").unwrap();
        assert_eq!(a.to_hex(), "0000000000000000000000000000000000000012340000abcdef000055550066");

        let a = FieldElement::from_hex("12340000abcdef000055550066").unwrap();
        assert_eq!(a.to_hex(), "0000000000000000000000000000000000000012340000abcdef000055550066");

        let a = FieldElement::from_str_vartime("9876541200300400500").unwrap();
        let v: u64 = 9_876_541_200_300_400_500;
        assert_eq!(a.to_hex(), format!("{v:064x}"));

        let a =
            FieldElement::from_str_vartime("18586133768512220936620570745912940619677854269274689475585506675881198879027")
                .unwrap();
        assert_eq!(
            a.to_string(),
            "Fr(0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133)"
        );

        let a =
            FieldElement::from_str_vartime("4417881134626180770308697923359573201005643519861877412381846989312604493735")
                .unwrap();
        assert_eq!(
            a.to_string(),
            "Fr(0x09c46e9ec68e9bd4fe1faaba294cba38a71aa177534cdd1b6c7dc0dbd0abd7a7)"
        );
    }

    #[test]
    fn properties() {
        let mut rng = &mut rand::thread_rng();
        for _ in 0..100 {
            let a = FieldElement::random(&mut rng);
            let b = FieldElement::random(&mut rng);
            assert_eq!(a * b, b * a); // commutative
            assert_eq!(a + b, b + a); // commutative
            assert_eq!(a * (b * a.invert().unwrap()), b); // division
            assert_eq!(a + (b - a), b); // subtraction
            assert_eq!(a + FieldElement::ZERO, a); // additive identity
            assert_eq!(a * (a + b), a.square() + a * b); // multiplicative identity
        }
    }

    /// Run the standard field tests from ff-group-tests
    #[test]
    fn test_field() {
        let mut rng = &mut rand::thread_rng();
        ff_group_tests::field::test_field::<_, FieldElement>(&mut rng);
        ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand::thread_rng());
    }

    #[cfg_attr(feature = "zeroize", test)]
    #[cfg(feature = "zeroize")]
    fn zeroize() {
        use zeroize::Zeroize;

        let mut f = FieldElement::ONE;
        f.zeroize();
    }
}
