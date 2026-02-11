use crate::error::ReadError;
use crate::grease_protocol::utils::Readable;
use flexible_transcript::{SecureDigest, Transcript};
use hex::{FromHex, FromHexError, ToHex};
use modular_frost::sign::Writable;
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

/// A 256 bit hash-based commitment to some data, using a specific hash algorithm D.
#[derive(Debug, Clone)]
pub struct HashCommitment256<D: SecureDigest> {
    data: [u8; 32],
    _phantom_data: PhantomData<D>,
}

impl<D: SecureDigest> HashCommitment256<D> {
    /// Create a new hash commitment from the provided data.
    pub fn new(data: [u8; 32]) -> Self {
        HashCommitment256 { data, _phantom_data: PhantomData }
    }

    /// Get the raw bytes of the commitment.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl<D: SecureDigest> Readable for HashCommitment256<D> {
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ReadError> {
        let mut data = [0u8; 32];
        reader.read_exact(&mut data).map_err(|e| ReadError::new("HashCommitment256", e.to_string()))?;
        Ok(HashCommitment256 { data, _phantom_data: PhantomData })
    }
}

impl<D: SecureDigest> Writable for HashCommitment256<D> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.data[..])
    }
}

impl<D: SecureDigest> ToHex for HashCommitment256<D> {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode(self.data);
        s.chars().collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode_upper(self.data);
        s.chars().collect()
    }
}

impl<D: SecureDigest> FromHex for HashCommitment256<D> {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut data = [0u8; 32];
        hex::decode_to_slice(hex, &mut data)?;
        Ok(HashCommitment256 { data, _phantom_data: PhantomData })
    }
}

impl<D: SecureDigest> PartialEq for HashCommitment256<D> {
    fn eq(&self, other: &Self) -> bool {
        // We only need to compare `data`.
        // The *compiler* won't let you compare commitments made from different hash algorithms!
        self.data == other.data
    }
}

impl<D: SecureDigest> Eq for HashCommitment256<D> {}

impl<D: SecureDigest> Serialize for HashCommitment256<D> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        hex::encode(self.data).serialize(s)
    }
}

impl<'de, D: SecureDigest> Deserialize<'de> for HashCommitment256<D> {
    fn deserialize<De: Deserializer<'de>>(de: De) -> Result<Self, De::Error> {
        let hex_str = String::deserialize(de)?;
        let mut data = [0u8; 32];
        hex::decode_to_slice(&hex_str, &mut data).map_err(serde::de::Error::custom)?;
        Ok(Self::new(data))
    }
}
