use crate::cryptography::keys::Curve25519Secret;
use crate::error::ReadError;
use crate::grease_protocol::utils::{read_group_element, write_group_element, Readable};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::ff::{Field, PrimeField, PrimeFieldBits};
use ciphersuite::group::Group;
use ciphersuite::{Ciphersuite, Ed25519};
use dalek_ff_group::EdwardsPoint;
use dleq::cross_group::scalar::scalar_convert as dleq_scalar_convert;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::{Debug, Formatter};
use std::io::Write;
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
pub enum CrossCurveError {
    /// The provided scalar is not valid in the target foreign curve's scalar field.
    #[error("The scalar is not valid in the foreign curve's scalar field")]
    InvalidScalar,
}

/// Try to convert a scalar between fields using serai's DLEQ-compatible conversion.
///
/// This uses the same algorithm as the DLEQ proof library to ensure consistency.
/// The conversion only succeeds if the scalar's value fits within the mutual capacity
/// of both fields (i.e., no bits are set beyond `min(From::CAPACITY, To::CAPACITY)`).
///
/// Returns `Some(to_scalar)` if the scalar is mutually valid in both fields,
/// `None` otherwise.
pub fn convert_scalar_dleq<From: PrimeFieldBits + Zeroize, To: PrimeFieldBits>(scalar: &From) -> Option<To> {
    // Clone the scalar since dleq_scalar_convert takes ownership and zeroizes
    let scalar_copy = *scalar;
    dleq_scalar_convert::<From, To>(scalar_copy)
}

/// In Grease, every update's adapter signature offset is a valid scalar on both the Ed25519 curve and the SNARK-friendly curve C used in the VCOF proofs.
/// The initial offset, is also a valid scalar on both Ed25519 and the KES's reference curve.
///
/// [`CrossCurveScalar`] is an abstraction over the math and verification checks for such a scalar. An instance of this type is guaranteed
/// to be a valid scalar on both Ed25519 and the Foreign curve, `C`.  
///
/// ## De- and Serialization
///
/// The [`CrossCurveScalar`] serializes and deserializes via its Ed25519 scalar representation, which encrypts the
/// value at rest.
///
/// On deserialization, the scalar is validated to ensure it is also valid in the foreign curve's scalar field.
///
/// # Panics
///
/// Panics if called without an active encryption context. Use
/// [`with_encryption_context`](crate::cryptography::encryption_context::with_encryption_context)
/// to wrap serialization operations.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCurveScalar<C: Ciphersuite> {
    offset: Zeroizing<XmrScalar>,
    _foreign_curve: PhantomData<C>,
}

impl<C: Ciphersuite> Debug for CrossCurveScalar<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("CrossCurveScalar(***hidden***)")
    }
}

impl<C: Ciphersuite> Serialize for CrossCurveScalar<C> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let secret = Curve25519Secret::from(*self.offset);
        secret.serialize(serializer)
    }
}

impl<'de, C: Ciphersuite> Deserialize<'de> for CrossCurveScalar<C>
where
    C::F: PrimeFieldBits,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let offset = Curve25519Secret::deserialize(deserializer)?;
        // Validate that it's also valid in C using DLEQ-compatible conversion
        if convert_scalar_dleq::<XmrScalar, C::F>(offset.as_scalar()).is_none() {
            return Err(serde::de::Error::custom("Scalar is not valid in the FOREIGN curve"));
        }
        Ok(Self { offset: offset.to_scalar(), _foreign_curve: PhantomData })
    }
}

impl<C: Ciphersuite> CrossCurveScalar<C> {
    /// Create a new random [`CrossCurveScalar`] that is valid in both Ed25519 and C's scalar field.
    ///
    /// The strategy is to sample random scalars from C's field until we find one whose byte
    /// representation is also a valid Ed25519 scalar. For most curve combinations this succeeds
    /// on the first attempt.
    pub fn random() -> Self {
        Self::random_with_rng(&mut OsRng)
    }

    /// Try to create a [`CrossCurveScalar`] from a foreign curve scalar.
    ///
    /// This will fail if the scalar is not mutually valid in both Ed25519 and C fields.
    pub fn try_from_foreign_scalar(scalar: C::F) -> Result<Self, CrossCurveError>
    where
        C::F: PrimeFieldBits,
    {
        let offset = convert_scalar_dleq::<C::F, XmrScalar>(&scalar).ok_or(CrossCurveError::InvalidScalar)?;
        Ok(Self { offset: Zeroizing::new(offset), _foreign_curve: PhantomData })
    }

    /// Try to create a [`CrossCurveScalar`] from little-endian bytes.
    ///
    /// This will fail if the bytes do not represent a valid scalar in both Ed25519 and C.
    pub fn try_from_le_bytes(bytes: &[u8; 32]) -> Result<Self, CrossCurveError>
    where
        C::F: PrimeFieldBits,
    {
        let mut repr = <XmrScalar as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(bytes);
        let offset = XmrScalar::from_repr(repr).into_option().ok_or(CrossCurveError::InvalidScalar)?;

        // Also validate it's mutually valid in C using DLEQ-compatible conversion
        if convert_scalar_dleq::<XmrScalar, C::F>(&offset).is_none() {
            return Err(CrossCurveError::InvalidScalar);
        }

        Ok(Self { offset: Zeroizing::new(offset), _foreign_curve: PhantomData })
    }

    /// Try to create a [`CrossCurveScalar`] from big-endian bytes.
    ///
    /// This will fail if the bytes do not represent a valid scalar in both Ed25519 and C.
    pub fn try_from_be_bytes(bytes: &[u8; 32]) -> Result<Self, CrossCurveError>
    where
        C::F: PrimeFieldBits,
    {
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

    /// Create a new random [`CrossCurveScalar`] using the provided RNG.
    ///
    /// Uses rejection sampling to find a scalar that is mutually valid in both Ed25519 and C
    /// according to the DLEQ proof library's requirements. This ensures the generated witness
    /// can be used with `generate_dleq` without failure.
    pub fn random_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self
    where
        C::F: PrimeFieldBits,
    {
        // Loop until we find a scalar that passes DLEQ-compatible conversion in both directions.
        // For most curve pairs, this succeeds quickly since the mutual capacity is close to both fields.
        const MAX_ITERS: usize = 256;
        let mut iters = 0;
        loop {
            iters += 1;
            let offset = XmrScalar::random(&mut *rng);
            if convert_scalar_dleq::<XmrScalar, C::F>(&offset).is_some() {
                return Self { offset: Zeroizing::new(offset), _foreign_curve: PhantomData };
            }
            // If this fails it means that there is probably than an 8-bit difference in security between the curves.
            if iters >= MAX_ITERS {
                panic!(
                    "Failed to generate a valid CrossCurveScalar after {MAX_ITERS} attempts. Are the two curves \
                close enough in field order?"
                );
            }
        }
    }

    /// Get the offset scalar converted to curve C's scalar field.
    ///
    /// This is guaranteed to succeed since the witness was constructed to be valid in both fields.
    pub fn as_foreign_scalar(&self) -> C::F
    where
        C::F: PrimeFieldBits,
    {
        convert_scalar_dleq::<XmrScalar, C::F>(&self.offset)
            .expect("CrossCurveScalar invariant violated: offset should be valid on the foreign curve")
    }

    /// Get the public points corresponding to this witness.
    pub fn public_points(&self) -> CrossCurvePoints<C>
    where
        C::F: PrimeFieldBits,
    {
        let xmr_point = EdwardsPoint::generator() * *self.offset;
        let foreign_scalar = self.as_foreign_scalar();
        let foreign_point = C::G::generator() * foreign_scalar;
        CrossCurvePoints { xmr_point, foreign_point }
    }
}

impl<C: Ciphersuite> Offset for CrossCurveScalar<C>
where
    C::F: PrimeFieldBits,
{
    type Public = CrossCurvePoints<C>;

    /// Get the offset scalar as an Ed25519 scalar.
    fn offset(&self) -> &XmrScalar {
        &self.offset
    }

    fn as_public(&self) -> Self::Public {
        self.public_points()
    }
}

impl<C: Ciphersuite> TryFrom<XmrScalar> for CrossCurveScalar<C>
where
    C::F: PrimeFieldBits,
{
    type Error = CrossCurveError;

    /// Try to create a [`CrossCurveScalar`] from an Ed25519 scalar.
    ///
    /// This will fail if the scalar is not mutually valid in both Ed25519 and C fields.
    fn try_from(offset: XmrScalar) -> Result<Self, Self::Error> {
        if convert_scalar_dleq::<XmrScalar, C::F>(&offset).is_some() {
            Ok(Self { offset: Zeroizing::new(offset), _foreign_curve: PhantomData })
        } else {
            Err(CrossCurveError::InvalidScalar)
        }
    }
}

impl<C: Ciphersuite> Zeroize for CrossCurveScalar<C> {
    fn zeroize(&mut self) {
        self.offset.zeroize();
    }
}

/// The public point counterpart to [`CrossCurveScalar`]. It holds both the Ed25519 point and the foreign curve point.
///
/// The points are *NOT* guaranteed to be equivalent, however. This can only be proved via a corresponding DLEQ proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossCurvePoints<C: Ciphersuite> {
    xmr_point: XmrPoint,
    foreign_point: C::G,
}

impl<C: Ciphersuite> CrossCurvePoints<C> {
    /// Create new `CrossCurvePoints` from the given points.
    ///
    /// Note: This does not verify that the points are equivalent - that requires a DLEQ proof.
    pub fn new(xmr_point: XmrPoint, foreign_point: C::G) -> Self {
        Self { xmr_point, foreign_point }
    }

    /// Get the foreign curve point.
    pub fn foreign_point(&self) -> &C::G {
        &self.foreign_point
    }
}

impl<C: Ciphersuite> AsXmrPoint for CrossCurvePoints<C> {
    fn as_xmr_point(&self) -> &XmrPoint {
        &self.xmr_point
    }
}

impl<C: Ciphersuite> Writable for CrossCurvePoints<C> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        write_group_element::<Ed25519, W>(writer, &self.xmr_point)?;
        write_group_element::<C, W>(writer, &self.foreign_point)?;
        Ok(())
    }
}

impl<C: Ciphersuite> Readable for CrossCurvePoints<C> {
    fn read<R: std::io::Read>(reader: &mut R) -> Result<Self, ReadError> {
        let xmr_point = read_group_element::<Ed25519, R>(reader)
            .map_err(|e| ReadError::new("CrossCurvePoints", format!("Failed to read XMR point: {e}")))?;
        let foreign_point = read_group_element::<C, R>(reader)
            .map_err(|e| ReadError::new("CrossCurvePoints", format!("Failed to read foreign point: {e}")))?;
        Ok(Self::new(xmr_point, foreign_point))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption, EncryptionContext};
    use ciphersuite::{Ed25519, Secp256k1};
    use grease_babyjubjub::{BabyJubJub, Scalar as BjjScalar};
    use std::sync::Arc;

    fn test_encryption_context() -> Arc<dyn EncryptionContext> {
        Arc::new(AesGcmEncryption::random())
    }

    #[test]
    fn random_witness_ed25519_is_valid() {
        // Ed25519 -> Ed25519 should always work since they're the same curve
        for _ in 0..100 {
            let witness = CrossCurveScalar::<Ed25519>::random();
            let offset = witness.offset();

            // Should be able to convert back
            let witness2 = CrossCurveScalar::<Ed25519>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());

            // Should be able to get as foreign scalar
            let foreign_scalar = witness.as_foreign_scalar();
            assert_eq!(*offset, foreign_scalar, "Ed25519 scalar should round-trip");
        }
    }

    #[test]
    fn random_witness_babyjubjub_is_valid() {
        // BabyJubJub has a smaller order than Ed25519, so random witnesses should be valid in both
        for _ in 0..100 {
            let witness = CrossCurveScalar::<BabyJubJub>::random();
            let offset = witness.offset();
            // Should be able to get as foreign scalar
            let foreign_scalar = witness.as_foreign_scalar();

            // Should be able to convert back
            let witness2 = CrossCurveScalar::<BabyJubJub>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());
            assert_eq!(foreign_scalar, witness.as_foreign_scalar());
        }
    }

    #[test]
    fn random_witness_secp256k1_is_valid() {
        // Secp256k1 has a larger order than Ed25519, so all Ed25519 scalars should be valid
        for _ in 0..100 {
            let witness = CrossCurveScalar::<Secp256k1>::random();
            let offset = witness.offset();

            // Should be able to convert back
            let witness2 = CrossCurveScalar::<Secp256k1>::try_from(*offset).expect("Should be valid");
            assert_eq!(witness.offset(), witness2.offset());

            // Should be able to get as foreign scalar
            let _foreign_scalar = witness.as_foreign_scalar();
        }
    }

    #[test]
    fn try_from_valid_scalar_ed25519() {
        let scalar = XmrScalar::random(&mut OsRng);
        let witness = CrossCurveScalar::<Ed25519>::try_from(scalar);
        assert!(witness.is_ok(), "Any Ed25519 scalar should be valid for Ed25519");
        assert_eq!(*witness.unwrap().offset(), scalar);
    }

    #[test]
    fn try_from_valid_scalar_secp256k1() {
        // Secp256k1's order is larger than Ed25519's, so any Ed25519 scalar should be valid
        for _ in 0..100 {
            let scalar = XmrScalar::random(&mut OsRng);
            let witness = CrossCurveScalar::<Secp256k1>::try_from(scalar);
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
                let witness = CrossCurveScalar::<BabyJubJub>::try_from(large_scalar);
                if let Err(e) = witness {
                    assert_eq!(e, CrossCurveError::InvalidScalar);
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
        let ctx = test_encryption_context();
        let witness = CrossCurveScalar::<BabyJubJub>::random();
        let serialized =
            with_encryption_context(ctx.clone(), || ron::to_string(&witness).expect("Serialization should succeed"));
        let deserialized: CrossCurveScalar<BabyJubJub> =
            with_encryption_context(ctx, || ron::from_str(&serialized).expect("Deserialization should succeed"));
        assert_eq!(witness.offset(), deserialized.offset());
    }

    #[test]
    fn witness_zero_scalar() {
        // Zero should be valid in all curves
        let zero = XmrScalar::from(0u64);

        let witness_ed = CrossCurveScalar::<Ed25519>::try_from(zero);
        assert!(witness_ed.is_ok(), "Zero should be valid for Ed25519");

        let witness_bjj = CrossCurveScalar::<BabyJubJub>::try_from(zero);
        assert!(witness_bjj.is_ok(), "Zero should be valid for BabyJubJub");

        let witness_secp = CrossCurveScalar::<Secp256k1>::try_from(zero);
        assert!(witness_secp.is_ok(), "Zero should be valid for Secp256k1");
    }

    #[test]
    fn witness_one_scalar() {
        // One should be valid in all curves
        let one = XmrScalar::from(1u64);

        let witness_ed = CrossCurveScalar::<Ed25519>::try_from(one);
        assert!(witness_ed.is_ok(), "One should be valid for Ed25519");
        assert_eq!(witness_ed.unwrap().as_foreign_scalar(), XmrScalar::from(1u64));

        let witness_bjj = CrossCurveScalar::<BabyJubJub>::try_from(one);
        assert!(witness_bjj.is_ok(), "One should be valid for BabyJubJub");

        let witness_secp = CrossCurveScalar::<Secp256k1>::try_from(one);
        assert!(witness_secp.is_ok(), "One should be valid for Secp256k1");
    }

    #[test]
    fn witness_small_values_valid_everywhere() {
        // Small values should be valid in all curves
        for i in 0u64..1000 {
            let scalar = XmrScalar::from(i);

            assert!(CrossCurveScalar::<Ed25519>::try_from(scalar).is_ok());
            assert!(CrossCurveScalar::<BabyJubJub>::try_from(scalar).is_ok());
            assert!(CrossCurveScalar::<Secp256k1>::try_from(scalar).is_ok());
        }
    }

    #[test]
    fn as_foreign_scalar_roundtrip() {
        // Test that as_foreign_scalar returns a value that, when converted back to bytes,
        // matches the original offset bytes
        for _ in 0..100 {
            let witness = CrossCurveScalar::<BabyJubJub>::random();
            let offset = witness.offset();
            let foreign_scalar = witness.as_foreign_scalar();

            // Convert foreign scalar back to bytes
            let foreign_bytes = foreign_scalar.to_repr();
            let offset_bytes = offset.to_repr();

            // The bytes should match (at least for the overlapping portion)
            assert_eq!(
                &foreign_bytes[..],
                &offset_bytes[..],
                "Scalar bytes should match after roundtrip"
            );
        }
    }

    #[test]
    fn different_curves_same_value() {
        // A small value should produce equivalent witnesses across curves
        let value = XmrScalar::from(42u64);

        let witness_ed = CrossCurveScalar::<Ed25519>::try_from(value).unwrap();
        let witness_bjj = CrossCurveScalar::<BabyJubJub>::try_from(value).unwrap();
        let witness_secp = CrossCurveScalar::<Secp256k1>::try_from(value).unwrap();

        // All should have the same offset
        assert_eq!(witness_ed.offset(), witness_bjj.offset());
        assert_eq!(witness_bjj.offset(), witness_secp.offset());
    }

    #[test]
    fn witness_equality() {
        let witness1 = CrossCurveScalar::<BabyJubJub>::random();
        let witness2 = CrossCurveScalar::<BabyJubJub>::try_from(*witness1.offset()).unwrap();

        assert_eq!(witness1, witness2, "Witnesses with same offset should be equal");

        let witness3 = CrossCurveScalar::<BabyJubJub>::random();
        // Very unlikely to be equal due to randomness
        if witness1.offset() != witness3.offset() {
            assert_ne!(witness1, witness3, "Witnesses with different offsets should not be equal");
        }
    }

    #[test]
    fn witness_clone() {
        let witness = CrossCurveScalar::<BabyJubJub>::random();
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
            let witness = CrossCurveScalar::<BabyJubJub>::try_from(under_order);
            assert!(witness.is_ok(), "Value under BabyJubJub order should be valid");
        }
    }

    #[test]
    fn error_display() {
        let err = CrossCurveError::InvalidScalar;
        let display = format!("{err}");
        assert!(display.contains("not valid"), "Error message should mention validity");
    }

    #[test]
    fn serialization_preserves_validity() {
        let ctx = test_encryption_context();
        // Test that serialization and deserialization preserve the validity invariant
        for _ in 0..10 {
            let witness = CrossCurveScalar::<BabyJubJub>::random();

            // Serialize and deserialize with RON
            let ron_str = with_encryption_context(ctx.clone(), || {
                ron::to_string(&witness).expect("RON serialization should succeed")
            });
            let from_ron: CrossCurveScalar<BabyJubJub> = with_encryption_context(ctx.clone(), || {
                ron::from_str(&ron_str).expect("RON deserialization should succeed")
            });

            // Verify it matches
            assert_eq!(witness.offset(), from_ron.offset());

            // Verify it's still valid in C
            assert!(convert_scalar_dleq::<XmrScalar, BjjScalar>(from_ron.offset()).is_some());
        }
    }

    #[test]
    fn deserialization_rejects_invalid_ed25519() {
        // Test that deserialization rejects a value >= Ed25519 order
        // 0xffffffff... is > Ed25519 order, so Ed25519::from_repr should reject it
        let invalid = "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"";
        let result: Result<CrossCurveScalar<BabyJubJub>, _> = ron::from_str(invalid);
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
        let result: Result<CrossCurveScalar<BabyJubJub>, _> = ron::from_str(&ron_str);
        assert!(
            result.is_err(),
            "Should reject value valid in Ed25519 but invalid in BabyJubJub"
        );
    }
}
