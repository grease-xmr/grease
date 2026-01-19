//! Mock VCOF implementation for testing.
//!
//! This module provides a fast but insecure VCOF implementation that can be used in tests.
//! It provides verifiability and consecutiveness, but NOT one-wayness.

use crate::cryptography::vcof::{VcofError, VcofProofInput, VcofProofResult, VerifiableConsecutiveOnewayFunction};
use crate::error::ReadError;
use crate::grease_protocol::utils::{read_group_element, write_group_element, Readable};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use modular_frost::sign::Writable;
use monero::consensus::ReadExt;
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// A mock VCOF implementation for testing.
///
/// This implementation is NOT cryptographically secure - it provides no one-wayness since anyone
/// with the seed public key can compute subsequent values. However, it does provide:
/// - **Verifiability**: Proofs can be verified to confirm correct derivation
/// - **Consecutiveness**: Each value depends deterministically on the seed public key and index
///
/// The next value is computed as: `H(seed_pub || index)` where H is a hash-to-scalar function.
#[derive(Clone, Debug)]
pub struct MockVCOF {
    /// The original seed public key used for all derivations.
    seed_pub: XmrPoint,
}

impl MockVCOF {
    /// Create a new MockVCOF with the given seed public key.
    pub fn new(seed_pub: XmrPoint) -> Self {
        Self { seed_pub }
    }

    /// Hash the seed public key and index to produce a scalar.
    pub fn witness_i(&self, index: u64) -> XmrScalar {
        let mut bytes = self.seed_pub.to_bytes().as_ref().to_vec();
        bytes.extend_from_slice(&index.to_le_bytes());
        Ed25519::hash_to_F(b"MockVCOF", &bytes)
    }
}

/// Proof for MockVCOF that stores the seed public key and index used for derivation.
///
/// Verification recomputes `H(seed_pub | index)` and checks that `G * result == next_pub`.
#[derive(Clone, Debug)]
pub struct MockVcofProof {
    vcof: MockVCOF,
    index: u64,
}

impl Writable for MockVcofProof {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        write_group_element::<Ed25519, _>(writer, &self.vcof.seed_pub)?;
        writer.write_all(&self.index.to_le_bytes())
    }
}

impl Readable for MockVcofProof {
    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ReadError> {
        let seed_pub = read_group_element::<Ed25519, _>(reader)
            .map_err(|_| ReadError::new("MockVcofProof", "failed to read group element"))?;
        let vcof = MockVCOF { seed_pub };
        let index = reader.read_u64().map_err(|e| ReadError::new("MockVcofProof", e.to_string()))?;
        Ok(MockVcofProof { vcof, index })
    }
}

impl VerifiableConsecutiveOnewayFunction<Ed25519> for MockVCOF {
    type Proof = MockVcofProof;
    type Context = ();

    fn compute_next(
        &self,
        update_count: u64,
        _: &XmrScalar,
        _: &XmrPoint,
        _ctx: &Self::Context,
    ) -> Result<XmrScalar, VcofError> {
        // Compute next as H(seed_pub || update_count)
        let next = self.witness_i(update_count);
        Ok(next)
    }

    fn create_proof(&self, input: &VcofProofInput<Ed25519>, ctx: &Self::Context) -> Result<Self::Proof, VcofError> {
        let proof = MockVcofProof { vcof: self.clone(), index: input.index };
        Ok(proof)
    }

    fn verify(
        &self,
        update_count: u64,
        prev: &XmrPoint,
        next: &XmrPoint,
        proof: &Self::Proof,
        _: &(),
    ) -> Result<(), VcofError> {
        if update_count < 1 {
            return Err(VcofError::InvalidProof);
        }

        if proof.index != update_count {
            return Err(VcofError::InvalidProof);
        }

        if update_count == 1 {
            if *prev != self.seed_pub {
                return Err(VcofError::InvalidProof);
            }
        } else {
            let expected_prev = self.witness_i(update_count - 1);
            let expected_prev_pub = Ed25519::generator() * expected_prev;

            if expected_prev_pub != *prev {
                return Err(VcofError::InvalidProof);
            }
        }
        let expected_next = self.witness_i(update_count);
        let expected_next_pub = Ed25519::generator() * expected_next;

        if expected_next_pub != *next {
            return Err(VcofError::InvalidProof);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;
    use rand_core::OsRng;

    #[test]
    fn test_mock_vcof_consecutiveness() {
        // Create initial seed
        let seed = Zeroizing::new(XmrScalar::random(&mut OsRng));
        let pub0 = Ed25519::generator() * *seed;
        // Create initial record and VCOF instance

        let vcof = MockVCOF::new(pub0.clone());

        let p1 = vcof.next(1, &seed, &pub0, &()).unwrap();
        // Advance to next record
        assert_eq!(p1.input.index, 1);

        vcof.verify(1, &p1.input.prev_pub, &p1.input.next_pub, &p1.proof, &()).unwrap();

        // Advance again
        let p2 = vcof.next(2, &p1.input.next, &p1.input.next_pub, &()).unwrap();
        assert_eq!(p2.input.index, 2);
        assert_eq!(p2.input.prev_pub, p1.input.next_pub);
        vcof.verify(2, &p2.input.prev_pub, &p2.input.next_pub, &p2.proof, &()).unwrap();
    }

    #[test]
    fn test_mock_vcof_invalid_proof() {
        let seed = Zeroizing::new(XmrScalar::random(&mut OsRng));
        let pub0 = Ed25519::generator() * *seed;
        let vcof = MockVCOF::new(pub0);

        let p1 = vcof.next(1, &seed, &pub0, &()).unwrap();

        // Create a proof with wrong index
        let bad_proof = MockVcofProof { vcof: vcof.clone(), index: 999 };
        let result = vcof.verify(1, &p1.input.prev_pub, &p1.input.next_pub, &bad_proof, &());
        assert!(matches!(result, Err(VcofError::InvalidProof)));

        // Verify with wrong update_count
        let result = vcof.verify(2, &p1.input.prev_pub, &p1.input.next_pub, &p1.proof, &());
        assert!(matches!(result, Err(VcofError::InvalidProof)));
    }
}
