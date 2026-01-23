use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::ff::{Field, PrimeField};
use ciphersuite::group::Group;
use ciphersuite::Ciphersuite;
use dalek_ff_group::EdwardsPoint;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// VCOFs can employ any kind of type as witness, as long as they can deliver an offset scalar.
///
/// This trait returns a reference to the offset scalar for security reasons. Implementors *must* take care to zeroize
/// the scalar when dropping the witness. By returning a reference, we avoid profligate copies of the scalar and callers
/// don't have to worry about zeroizing their copies. However, if you *do* need a copy, a simple de-reference will do:
///
/// ```nocompile
/// let secret = *Offset::offset();
/// // do secret things ...
/// secret.zeroize(); // Caller is responsible for zeroizing their own copies
/// ```
pub trait Offset: Clone + Zeroize {
    type Public: AsXmrPoint;
    fn offset(&self) -> &XmrScalar;
    fn as_public(&self) -> Self::Public;
}

pub trait AsXmrPoint {
    fn as_xmr_point(&self) -> &XmrPoint;
}

/// Error type for witness operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The provided scalar is not valid in the target SNARK curve's scalar field.
    #[error("The scalar is not valid in the SNARK curve's scalar field")]
    InvalidScalar,
}

/// Try to convert a scalar from ciphersuite `From` to ciphersuite `To`.
///
/// Returns `Some(to_scalar)` if the byte representation is valid in `To`'s scalar field,
/// `None` otherwise.
pub fn convert_scalar<From: PrimeField, To: PrimeField>(scalar: &From) -> Option<To> {
    let from_bytes = scalar.to_repr();
    let mut to_repr = To::Repr::default();
    let to_slice = to_repr.as_mut();
    let from_slice = from_bytes.as_ref();
    let copy_len = to_slice.len().min(from_slice.len());
    to_slice[..copy_len].copy_from_slice(&from_slice[..copy_len]);
    To::from_repr(to_repr).into_option()
}

/// A channel witness is the adapter signature offset represented in a form that is valid in a ZK-SNARK context.
///
/// Specifically, it is an Ed25519 scalar that is also guaranteed to be a valid scalar in the SNARK-friendly curve SF.
/// This dual validity is required for cross-curve operations in the payment channel protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct ChannelWitness<SF: Ciphersuite> {
    offset: Zeroizing<XmrScalar>,
    _snark_curve: PhantomData<SF>,
}

impl<SF: Ciphersuite> Debug for ChannelWitness<SF> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelWitness(***hidden***)")
    }
}

impl<SF: Ciphersuite> Serialize for ChannelWitness<SF> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = self.offset.to_repr();
        let result = crate::helpers::to_hex(bytes.as_ref(), serializer);
        bytes.zeroize();
        result
    }
}

impl<'de, SF: Ciphersuite> Deserialize<'de> for ChannelWitness<SF> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = crate::helpers::array_from_hex(deserializer)?;
        let offset = XmrScalar::from_repr(bytes)
            .into_option()
            .ok_or_else(|| serde::de::Error::custom("Invalid Ed25519 scalar"))?;
        // Validate that it's also valid in SF
        if convert_scalar::<XmrScalar, SF::F>(&offset).is_none() {
            return Err(serde::de::Error::custom("Scalar is not valid in the SNARK curve"));
        }
        Ok(Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData })
    }
}

impl<SF: Ciphersuite> ChannelWitness<SF> {
    /// Create a new random ChannelWitness that is valid in both Ed25519 and SF's scalar field.
    ///
    /// The strategy is to sample random scalars from SF's field until we find one whose byte
    /// representation is also a valid Ed25519 scalar. For most curve combinations this succeeds
    /// on the first attempt.
    pub fn random() -> Self {
        Self::random_with_rng(&mut OsRng)
    }

    /// Try to create a ChannelWitness from a SNARK curve scalar.
    ///
    /// This will fail if the scalar's byte representation is not a valid Ed25519 scalar.
    pub fn try_from_snark_scalar(scalar: SF::F) -> Result<Self, WitnessError> {
        let offset = convert_scalar::<SF::F, XmrScalar>(&scalar).ok_or(WitnessError::InvalidScalar)?;
        Ok(Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData })
    }

    /// Try to create a ChannelWitness from little-endian bytes.
    ///
    /// This will fail if the bytes do not represent a valid scalar in both Ed25519 and SF.
    pub fn try_from_le_bytes(bytes: &[u8; 32]) -> Result<Self, WitnessError> {
        let mut repr = <XmrScalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        let offset = XmrScalar::from_repr(repr).into_option().ok_or(WitnessError::InvalidScalar)?;

        // Also validate it's valid in SF
        if convert_scalar::<XmrScalar, SF::F>(&offset).is_none() {
            return Err(WitnessError::InvalidScalar);
        }

        Ok(Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData })
    }

    /// Try to create a ChannelWitness from big-endian bytes.
    ///
    /// This will fail if the bytes do not represent a valid scalar in both Ed25519 and SF.
    pub fn try_from_be_bytes(bytes: &[u8; 32]) -> Result<Self, WitnessError> {
        let mut bytes = *bytes;
        bytes.reverse();
        let result = Self::try_from_le_bytes(&bytes);
        bytes.zeroize();
        result
    }

    /// Convert the witness offset to little-endian bytes.
    ///
    /// ## Security Note: Callers *must* call `zeroize()` on the returned byte array when done.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let repr = self.offset.to_repr();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(repr.as_ref());
        bytes
    }

    /// Create a new random ChannelWitness using the provided RNG.
    ///
    /// The sampling strategy is optimized based on the relative field sizes:
    /// - If SF's field is smaller (fewer bits), sample from SF (always valid in Ed25519)
    /// - If Ed25519's field is smaller, sample from Ed25519 (always valid in SF)
    /// - If equal bits, loop until we find a value valid in both (average ~2 iterations)
    pub fn random_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        use std::cmp::Ordering;

        match <SF::F as PrimeField>::NUM_BITS.cmp(&<XmrScalar as PrimeField>::NUM_BITS) {
            Ordering::Less => {
                // SF's field is smaller - any SF scalar fits in Ed25519
                let sf_scalar = SF::F::random(&mut *rng);
                let offset = convert_scalar::<SF::F, XmrScalar>(&sf_scalar)
                    .expect("SF scalar with fewer bits should always be valid in Ed25519");
                Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData }
            }
            Ordering::Greater => {
                // Ed25519's field is smaller - any Ed25519 scalar fits in SF
                let offset = XmrScalar::random(&mut *rng);
                debug_assert!(convert_scalar::<XmrScalar, SF::F>(&offset).is_some());
                Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData }
            }
            Ordering::Equal => {
                // Same bit size - need to loop, but average ~2 iterations
                loop {
                    let sf_scalar = SF::F::random(&mut *rng);
                    if let Some(offset) = convert_scalar::<SF::F, XmrScalar>(&sf_scalar) {
                        debug_assert!(convert_scalar::<XmrScalar, SF::F>(&offset).is_some());
                        return Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData };
                    }
                }
            }
        }
    }

    /// Get the offset scalar converted to curve SF's scalar field.
    ///
    /// This is guaranteed to succeed since the witness was constructed to be valid in both fields.
    pub fn as_snark_scalar(&self) -> SF::F {
        convert_scalar::<XmrScalar, SF::F>(&self.offset)
            .expect("ChannelWitness invariant violated: offset should be valid in SF")
    }

    /// Get the public points corresponding to this witness.
    pub fn public_points(&self) -> ChannelWitnessPublic<SF> {
        let xmr_point = EdwardsPoint::generator() * &*self.offset;
        let snark_scalar = self.as_snark_scalar();
        let snark_point = SF::G::generator() * &snark_scalar;
        ChannelWitnessPublic { xmr_point, snark_point }
    }
}

impl<SF: Ciphersuite> Offset for ChannelWitness<SF> {
    type Public = ChannelWitnessPublic<SF>;

    /// Get the offset scalar as an Ed25519 scalar.
    fn offset(&self) -> &XmrScalar {
        &self.offset
    }

    fn as_public(&self) -> Self::Public {
        self.public_points()
    }
}

impl<SF: Ciphersuite> TryFrom<XmrScalar> for ChannelWitness<SF> {
    type Error = WitnessError;

    /// Try to create a ChannelWitness from an Ed25519 scalar.
    ///
    /// This will fail if the scalar's byte representation is not a valid scalar in SF's field.
    fn try_from(offset: XmrScalar) -> Result<Self, Self::Error> {
        if convert_scalar::<XmrScalar, SF::F>(&offset).is_some() {
            Ok(Self { offset: Zeroizing::new(offset), _snark_curve: PhantomData })
        } else {
            Err(WitnessError::InvalidScalar)
        }
    }
}

impl<SF: Ciphersuite> Zeroize for ChannelWitness<SF> {
    fn zeroize(&mut self) {
        self.offset.zeroize();
    }
}

/// The public point counterpart to ChannelWitness. It holds both the Ed25519 point and the SNARK curve point.
///
/// The points are *NOT* guaranteed to be equivalent, however. This can only be proved via a corresponding DLEQ proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelWitnessPublic<SF: Ciphersuite> {
    xmr_point: XmrPoint,
    snark_point: SF::G,
}

impl<SF: Ciphersuite> ChannelWitnessPublic<SF> {
    /// Get the SNARK curve point.
    pub fn snark_point(&self) -> &SF::G {
        &self.snark_point
    }
}

impl<SF: Ciphersuite> AsXmrPoint for ChannelWitnessPublic<SF> {
    fn as_xmr_point(&self) -> &XmrPoint {
        &self.xmr_point
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::{Ed25519, Secp256k1};
    use grease_babyjubjub::{BabyJubJub, Scalar as BjjScalar};

    #[test]
    fn random_witness_ed25519_is_valid() {
        // Ed25519 -> Ed25519 should always work since they're the same curve
        for _ in 0..100 {
            let witness = ChannelWitness::<Ed25519>::random();
            let offset = witness.offset();

            // Should be able to convert back
            let witness2 = ChannelWitness::<Ed25519>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());

            // Should be able to get as SNARK scalar
            let snark_scalar = witness.as_snark_scalar();
            assert_eq!(*offset, snark_scalar, "Ed25519 scalar should round-trip");
        }
    }

    #[test]
    fn random_witness_babyjubjub_is_valid() {
        // BabyJubJub has a smaller order than Ed25519, so random witnesses should be valid in both
        for _ in 0..100 {
            let witness = ChannelWitness::<BabyJubJub>::random();
            let offset = witness.offset();

            // Should be able to convert back
            let witness2 = ChannelWitness::<BabyJubJub>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());

            // Should be able to get as SNARK scalar
            let _snark_scalar = witness.as_snark_scalar();
        }
    }

    #[test]
    fn random_witness_secp256k1_is_valid() {
        // Secp256k1 has a larger order than Ed25519, so all Ed25519 scalars should be valid
        for _ in 0..100 {
            let witness = ChannelWitness::<Secp256k1>::random();
            let offset = witness.offset();

            // Should be able to convert back
            let witness2 = ChannelWitness::<Secp256k1>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());

            // Should be able to get as SNARK scalar
            let _snark_scalar = witness.as_snark_scalar();
        }
    }

    #[test]
    fn try_from_valid_scalar_ed25519() {
        let scalar = XmrScalar::random(&mut OsRng);
        let witness = ChannelWitness::<Ed25519>::try_from(scalar);
        assert!(witness.is_ok(), "Any Ed25519 scalar should be valid for Ed25519");
        assert_eq!(*witness.unwrap().offset(), scalar);
    }

    #[test]
    fn try_from_valid_scalar_secp256k1() {
        // Secp256k1's order is larger than Ed25519's, so any Ed25519 scalar should be valid
        for _ in 0..100 {
            let scalar = XmrScalar::random(&mut OsRng);
            let witness = ChannelWitness::<Secp256k1>::try_from(scalar);
            assert!(witness.is_ok(), "Any Ed25519 scalar should be valid for Secp256k1");
        }
    }

    #[test]
    fn try_from_invalid_scalar_babyjubjub() {
        // BabyJubJub's order is smaller than Ed25519's order
        // BabyJubJub order: 2736030358979909402780800718157159386076813972158567259200215660948447373041
        // Ed25519 order: 7237005577332262213973186563042994240857116359379907606001950938285454250989
        //
        // We need to create an Ed25519 scalar that is >= BabyJubJub's order but < Ed25519's order

        // BabyJubJub modulus in LE hex (32 bytes):
        // 0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1
        // The high byte (byte 31) of BabyJubJub's modulus is 0x06

        // Create scalars with byte 31 = 0x07, which is > 0x06 but < 0x10 (Ed25519's high byte)
        // This should give valid Ed25519 scalars that exceed BabyJubJub's order

        let mut found_invalid = false;
        for high_byte in [0x07u8, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f] {
            let mut bytes = [0u8; 32];
            bytes[31] = high_byte;

            if let Some(large_scalar) = XmrScalar::from_repr(bytes).into_option() {
                let witness = ChannelWitness::<BabyJubJub>::try_from(large_scalar);
                if witness.is_err() {
                    assert_eq!(witness.unwrap_err(), WitnessError::InvalidScalar);
                    found_invalid = true;
                    break;
                }
            }
        }

        assert!(
            found_invalid,
            "Should find at least one scalar valid in Ed25519 but invalid in BabyJubJub"
        );
    }

    #[test]
    fn witness_serialization_roundtrip() {
        let witness = ChannelWitness::<BabyJubJub>::random();
        let serialized = ron::to_string(&witness).expect("Serialization should succeed");
        let deserialized: ChannelWitness<BabyJubJub> =
            ron::from_str(&serialized).expect("Deserialization should succeed");
        assert_eq!(witness.offset(), deserialized.offset());
    }

    #[test]
    fn witness_zero_scalar() {
        // Zero should be valid in all curves
        let zero = XmrScalar::from(0u64);

        let witness_ed = ChannelWitness::<Ed25519>::try_from(zero);
        assert!(witness_ed.is_ok(), "Zero should be valid for Ed25519");

        let witness_bjj = ChannelWitness::<BabyJubJub>::try_from(zero);
        assert!(witness_bjj.is_ok(), "Zero should be valid for BabyJubJub");

        let witness_secp = ChannelWitness::<Secp256k1>::try_from(zero);
        assert!(witness_secp.is_ok(), "Zero should be valid for Secp256k1");
    }

    #[test]
    fn witness_one_scalar() {
        // One should be valid in all curves
        let one = XmrScalar::from(1u64);

        let witness_ed = ChannelWitness::<Ed25519>::try_from(one);
        assert!(witness_ed.is_ok(), "One should be valid for Ed25519");
        assert_eq!(witness_ed.unwrap().as_snark_scalar(), XmrScalar::from(1u64));

        let witness_bjj = ChannelWitness::<BabyJubJub>::try_from(one);
        assert!(witness_bjj.is_ok(), "One should be valid for BabyJubJub");

        let witness_secp = ChannelWitness::<Secp256k1>::try_from(one);
        assert!(witness_secp.is_ok(), "One should be valid for Secp256k1");
    }

    #[test]
    fn witness_small_values_valid_everywhere() {
        // Small values should be valid in all curves
        for i in 0u64..1000 {
            let scalar = XmrScalar::from(i);

            assert!(ChannelWitness::<Ed25519>::try_from(scalar).is_ok());
            assert!(ChannelWitness::<BabyJubJub>::try_from(scalar).is_ok());
            assert!(ChannelWitness::<Secp256k1>::try_from(scalar).is_ok());
        }
    }

    #[test]
    fn as_snark_scalar_roundtrip() {
        // Test that as_snark_scalar returns a value that, when converted back to bytes,
        // matches the original offset bytes
        for _ in 0..100 {
            let witness = ChannelWitness::<BabyJubJub>::random();
            let offset = witness.offset();
            let snark_scalar = witness.as_snark_scalar();

            // Convert snark scalar back to bytes
            let snark_bytes = snark_scalar.to_repr();
            let offset_bytes = offset.to_repr();

            // The bytes should match (at least for the overlapping portion)
            assert_eq!(&snark_bytes[..], &offset_bytes[..], "Scalar bytes should match after roundtrip");
        }
    }

    #[test]
    fn different_curves_same_value() {
        // A small value should produce equivalent witnesses across curves
        let value = XmrScalar::from(42u64);

        let witness_ed = ChannelWitness::<Ed25519>::try_from(value).unwrap();
        let witness_bjj = ChannelWitness::<BabyJubJub>::try_from(value).unwrap();
        let witness_secp = ChannelWitness::<Secp256k1>::try_from(value).unwrap();

        // All should have the same offset
        assert_eq!(witness_ed.offset(), witness_bjj.offset());
        assert_eq!(witness_bjj.offset(), witness_secp.offset());
    }

    #[test]
    fn witness_equality() {
        let witness1 = ChannelWitness::<BabyJubJub>::random();
        let witness2 = ChannelWitness::<BabyJubJub>::try_from(*witness1.offset()).unwrap();

        assert_eq!(witness1, witness2, "Witnesses with same offset should be equal");

        let witness3 = ChannelWitness::<BabyJubJub>::random();
        // Very unlikely to be equal due to randomness
        if witness1.offset() != witness3.offset() {
            assert_ne!(witness1, witness3, "Witnesses with different offsets should not be equal");
        }
    }

    #[test]
    fn witness_clone() {
        let witness = ChannelWitness::<BabyJubJub>::random();
        let cloned = witness.clone();
        assert_eq!(witness.offset(), cloned.offset());
    }

    #[test]
    fn babyjubjub_boundary_values() {
        // Test values near BabyJubJub's order boundary
        // BabyJubJub modulus: 2736030358979909402780800718157159386076813972158567259200215660948447373041
        // This is approximately 2^251

        // Value just under the BabyJubJub order should be valid
        // We'll construct a value that's clearly under the order
        let mut under_order_bytes = [0u8; 32];
        under_order_bytes[30] = 0x05; // Sets a value around 2^248, well under 2^251
        under_order_bytes[0] = 0xff;

        if let Some(under_order) = XmrScalar::from_repr(under_order_bytes).into_option() {
            let witness = ChannelWitness::<BabyJubJub>::try_from(under_order);
            assert!(witness.is_ok(), "Value under BabyJubJub order should be valid");
        }
    }

    #[test]
    fn error_display() {
        let err = WitnessError::InvalidScalar;
        let display = format!("{err}");
        assert!(display.contains("not valid"), "Error message should mention validity");
    }

    #[test]
    fn convert_scalar_consistency() {
        // Test that convert_scalar is consistent
        for _ in 0..100 {
            let witness = ChannelWitness::<BabyJubJub>::random();
            let offset = witness.offset();

            // Ed25519 -> BabyJubJub should succeed
            let c_scalar = convert_scalar::<XmrScalar, BjjScalar>(offset);
            assert!(c_scalar.is_some(), "Conversion should succeed for valid witness");

            // BabyJubJub -> Ed25519 should round-trip
            let c = c_scalar.unwrap();
            let back = convert_scalar::<BjjScalar, XmrScalar>(&c);
            assert!(back.is_some(), "Roundtrip should succeed");
            assert_eq!(back.unwrap(), *offset, "Roundtrip should preserve value");
        }
    }

    #[test]
    fn convert_scalar_ed25519_identity() {
        // Ed25519 -> Ed25519 should always work
        for _ in 0..100 {
            let scalar = XmrScalar::random(&mut OsRng);
            let converted = convert_scalar::<XmrScalar, XmrScalar>(&scalar);
            assert!(converted.is_some());
            assert_eq!(converted.unwrap(), scalar);
        }
    }

    #[test]
    fn serialization_preserves_validity() {
        // Test that serialization and deserialization preserve the validity invariant
        for _ in 0..10 {
            let witness = ChannelWitness::<BabyJubJub>::random();

            // Serialize and deserialize with RON
            let ron_str = ron::to_string(&witness).expect("RON serialization should succeed");
            let from_ron: ChannelWitness<BabyJubJub> =
                ron::from_str(&ron_str).expect("RON deserialization should succeed");

            // Verify it matches
            assert_eq!(witness.offset(), from_ron.offset());

            // Verify it's still valid in C
            assert!(convert_scalar::<XmrScalar, BjjScalar>(from_ron.offset()).is_some());
        }
    }

    #[test]
    fn deserialization_rejects_invalid_ed25519() {
        // Test that deserialization rejects a value >= Ed25519 order
        // 0xffffffff... is > Ed25519 order, so Ed25519::from_repr should reject it
        let invalid = "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"";
        let result: Result<ChannelWitness<BabyJubJub>, _> = ron::from_str(invalid);
        assert!(result.is_err(), "Should reject value >= Ed25519 order during deserialization");
    }

    #[test]
    fn deserialization_rejects_invalid_babyjubjub() {
        // Test that deserialization rejects a value valid in Ed25519 but not in BabyJubJub
        // BabyJubJub order ≈ 2^251, Ed25519 order ≈ 2^252
        // A value in range [BJJ_order, Ed25519_order) should be rejected

        // Hex is LE bytes, first two chars = bytes[0], last two chars = bytes[31]
        // bytes[31] = 0x07 exceeds BabyJubJub's high byte (0x06) but is < Ed25519's (0x10)
        // This represents the integer 0x07 * 2^248 which is > BJJ order but < Ed25519 order
        let large_for_bjj = "0000000000000000000000000000000000000000000000000000000000000007";

        // Try to deserialize - should fail because it's invalid in BabyJubJub
        let ron_str = format!("\"{large_for_bjj}\"");
        let result: Result<ChannelWitness<BabyJubJub>, _> = ron::from_str(&ron_str);
        assert!(
            result.is_err(),
            "Should reject value valid in Ed25519 but invalid in BabyJubJub"
        );
    }
}
