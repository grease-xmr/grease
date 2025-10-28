use flexible_transcript::SecureDigest;
use hex::{FromHex, FromHexError, ToHex};
use modular_frost::sign::Writable;
use std::io::Write;
use std::marker::PhantomData;

/// A 256 bit hash-based commitment to some data, using a specific hash algorithm D.
#[derive(Debug, Clone)]
pub struct HashCommitment256<D: SecureDigest> {
    data: [u8; 32],
    _phantom_data: PhantomData<D>,
}

impl<D: SecureDigest> HashCommitment256<D> {
    /// Create a new hash commitment from the provided data.
    pub fn new(data: [u8; 32]) -> Self {
        HashCommitment256 { data, _phantom_data: PhantomData::default() }
    }

    /// Get the raw bytes of the commitment.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl<D: SecureDigest> Writable for HashCommitment256<D> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.data[..])
    }
}

impl<D: SecureDigest> ToHex for HashCommitment256<D> {
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode(&self.data);
        s.chars().collect()
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        let s = hex::encode_upper(&self.data);
        s.chars().collect()
    }
}

impl<D: SecureDigest> FromHex for HashCommitment256<D> {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut data = [0u8; 32];
        hex::decode_to_slice(hex, &mut data)?;
        Ok(HashCommitment256 { data, _phantom_data: PhantomData::default() })
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
