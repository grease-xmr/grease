use ciphersuite::group::ff::PrimeField;
use zeroize::{Zeroize, Zeroizing};

/// Trait for secret types that can be converted to/from bytes for encrypted serialization.
///
/// This enables [`SerializableSecret<T>`](super::serializable_secret::SerializableSecret) to
/// transparently encrypt any conforming type during serde.
pub trait SecretBytes: Zeroize + Sized {
    /// Serialize the secret value to bytes. The returned `Vec` is zeroized on drop.
    fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>>;

    /// Reconstruct the secret from bytes. Returns `None` if the bytes are invalid
    /// (wrong length, non-canonical, etc.).
    fn from_secret_bytes(bytes: &[u8]) -> Option<Self>;
}

/// Blanket impl for all `PrimeField + Zeroize` types.
///
/// This covers `XmrScalar` (Ed25519), `grumpkin::Scalar`, `BabyJubJub::Scalar`, etc.
impl<F> SecretBytes for F
where
    F: PrimeField + Zeroize,
    F::Repr: AsMut<[u8]>,
{
    fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.to_repr().as_ref().to_vec())
    }

    fn from_secret_bytes(bytes: &[u8]) -> Option<Self> {
        let mut repr = F::Repr::default();
        if bytes.len() != repr.as_ref().len() {
            return None;
        }
        repr.as_mut().copy_from_slice(bytes);
        F::from_repr(repr).into_option()
    }
}
