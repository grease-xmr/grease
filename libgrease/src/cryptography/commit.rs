use crate::error::ReadError;
use crate::grease_protocol::utils::Readable;
use crate::cryptography::SecureDigest;
use flexible_transcript::Transcript;
use hex::{FromHex, FromHexError, ToHex};
use crate::io::Writable;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::{Read, Write};
use std::marker::PhantomData;

pub trait Commit<D: SecureDigest> {
    type Committed: Clone + Writable + Eq + Readable;
    type Transcript: Transcript;
    fn commit(&self) -> Self::Committed;
    fn verify(&self, commitment: &Self::Committed) -> bool {
        self.commit() == *commitment
    }
}

/// An `N`-byte hash-based commitment to some data, using a specific hash algorithm D.
#[derive(Debug, Clone)]
pub struct HashCommitment<const N: usize, D: SecureDigest> {
    data: [u8; N],
    _phantom_data: PhantomData<D>,
}

/// A 256 bit hash-based commitment to some data, using a specific hash algorithm D.
pub type HashCommitment256<D> = HashCommitment<32, D>;

/// A 512 bit hash-based commitment to some data, using a specific hash algorithm D.
pub type HashCommitment512<D> = HashCommitment<64, D>;

impl<const N: usize, D: SecureDigest> HashCommitment<N, D> {
    /// Create a new hash commitment from the provided data.
    pub fn new(data: [u8; N]) -> Self {
        HashCommitment { data, _phantom_data: PhantomData }
    }

    /// Get the raw bytes of the commitment.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Copy the commitment's bytes into `out`.
    ///
    /// The destination is an array reference of exactly this commitment's width, so a wrongly sized buffer is a
    /// compile error rather than the runtime panic `copy_from_slice` would raise. Both sides are provably `N`
    /// bytes wide, so this cannot fail and copies in place rather than materialising an `[u8; N]` temporary.
    pub fn safe_copy(&self, out: &mut [u8; N]) {
        out.copy_from_slice(&self.data);
    }
}

impl<const N: usize, D: SecureDigest> Readable for HashCommitment<N, D> {
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ReadError> {
        let mut data = [0u8; N];
        reader.read_exact(&mut data).map_err(|e| ReadError::new("HashCommitment", e.to_string()))?;
        Ok(HashCommitment { data, _phantom_data: PhantomData })
    }
}

impl<const N: usize, D: SecureDigest> Writable for HashCommitment<N, D> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.data[..])
    }
}

impl<const N: usize, D: SecureDigest> ToHex for HashCommitment<N, D> {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode(self.data);
        s.chars().collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode_upper(self.data);
        s.chars().collect()
    }
}

impl<const N: usize, D: SecureDigest> FromHex for HashCommitment<N, D> {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut data = [0u8; N];
        hex::decode_to_slice(hex, &mut data)?;
        Ok(HashCommitment { data, _phantom_data: PhantomData })
    }
}

impl<const N: usize, D: SecureDigest> PartialEq for HashCommitment<N, D> {
    fn eq(&self, other: &Self) -> bool {
        // We only need to compare `data`.
        // The *compiler* won't let you compare commitments made from different hash algorithms!
        self.data == other.data
    }
}

impl<const N: usize, D: SecureDigest> Eq for HashCommitment<N, D> {}

impl<const N: usize, D: SecureDigest> Serialize for HashCommitment<N, D> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(self.data).serialize(s)
    }
}

impl<'de, const N: usize, D: SecureDigest> Deserialize<'de> for HashCommitment<N, D> {
    fn deserialize<De: Deserializer<'de>>(de: De) -> Result<Self, De::Error> {
        let hex_str = String::deserialize(de)?;
        let mut data = [0u8; N];
        hex::decode_to_slice(&hex_str, &mut data).map_err(serde::de::Error::custom)?;
        Ok(Self::new(data))
    }
}

#[cfg(test)]
mod test {
    use super::{HashCommitment256, HashCommitment512};
    use blake2::Blake2b512;

    #[test]
    fn commitment_safe_copy_round_trips() {
        let data = [7u8; 32];
        let commitment = HashCommitment256::<Blake2b512>::new(data);
        let mut out = [0u8; 32];
        commitment.safe_copy(&mut out);
        assert_eq!(out, data);
    }

    #[test]
    fn wide_commitment_safe_copy_round_trips() {
        let data: [u8; 64] = std::array::from_fn(|i| i as u8);
        let commitment = HashCommitment512::<Blake2b512>::new(data);
        let mut out = [0u8; 64];
        commitment.safe_copy(&mut out);
        assert_eq!(out, data);
    }
}
