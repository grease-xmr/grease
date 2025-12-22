use blake2::Digest;
use std::marker::PhantomData;

pub trait ByteCodeVerification: Default {
    fn calculate_checksum(&self, _bytecode: &[u8]) -> Vec<u8>;
    fn verify_bytecode(&self, bytecode: &[u8], expected_checksum: impl AsRef<[u8]>) -> bool {
        let calculated_checksum = self.calculate_checksum(bytecode);
        calculated_checksum.as_slice() == expected_checksum.as_ref()
    }
}

/// A dummy implementation of ByteCodeVerification that always returns true.
#[derive(Default)]
pub struct DummyByteCodeVerifier;

impl ByteCodeVerification for DummyByteCodeVerifier {
    fn calculate_checksum(&self, _bytecode: &[u8]) -> Vec<u8> {
        vec![]
    }

    fn verify_bytecode(&self, _bytecode: &[u8], _expected_checksum: impl AsRef<[u8]>) -> bool {
        true
    }
}

/// A hash-based implementation of ByteCodeVerification using the specified Digest algorithm.
#[derive(Default)]
pub struct HashByteCodeVerifier<D> {
    _digest: PhantomData<D>,
}

impl<D: Digest + Default> ByteCodeVerification for HashByteCodeVerifier<D> {
    fn calculate_checksum(&self, bytecode: &[u8]) -> Vec<u8> {
        let mut d = D::default();
        d.update(bytecode);
        d.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Blake2b512;

    #[test]
    fn test_dummy_verifier() {
        let verifier = DummyByteCodeVerifier::default();
        assert!(verifier.verify_bytecode(b"any bytecode", "any checksum"));
    }

    #[test]
    fn test_hash_verifier() {
        let verifier = HashByteCodeVerifier::<Blake2b512>::default();
        let bytecode = b"test bytecode";
        let mut hasher = Blake2b512::default();
        hasher.update(bytecode);
        let checksum = hasher.finalize().to_vec();

        assert!(verifier.verify_bytecode(bytecode, checksum.as_slice()));
        assert!(!verifier.verify_bytecode(bytecode, b"wrong checksum"));
    }
}
