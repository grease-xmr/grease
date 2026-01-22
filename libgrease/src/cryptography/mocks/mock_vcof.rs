//! Mock VCOF implementation for testing.
//!
//! This module provides a fast but insecure VCOF implementation that can be used in tests.
//! It provides verifiability and consecutiveness, but NOT one-wayness.

use crate::cryptography::vcof::{
    InvalidProof, ProvingError, VcofPrivateData, VcofPublicData, VerifiableConsecutiveOnewayFunction,
};
use crate::cryptography::witness::{AsXmrPoint, ChannelWitnessPublic};
use crate::cryptography::ChannelWitness;
use crate::error::ReadError;
use crate::grease_protocol::utils::{read_group_element, write_group_element, Readable};
use crate::{XmrPoint, XmrScalar};
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use modular_frost::sign::Writable;
use monero::consensus::ReadExt;
use std::io::{Read, Write};
use zeroize::Zeroize;

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

#[derive(Clone, Debug, Zeroize)]
pub struct MockVcofPrivateData {
    pub prev: ChannelWitness<Ed25519>,
    pub next: ChannelWitness<Ed25519>,
}

impl VcofPrivateData for MockVcofPrivateData {
    type W = ChannelWitness<Ed25519>;

    fn from_parts(prev: Self::W, next: Self::W) -> Self {
        Self { prev, next }
    }

    fn prev(&self) -> &Self::W {
        &self.prev
    }

    fn next(&self) -> &Self::W {
        &self.next
    }
}

#[derive(Clone, Debug)]
pub struct MockVcofPublicData {
    pub prev: ChannelWitnessPublic<Ed25519>,
    pub next: ChannelWitnessPublic<Ed25519>,
}

impl VcofPublicData for MockVcofPublicData {
    type G = ChannelWitnessPublic<Ed25519>;

    fn from_parts(prev: Self::G, next: Self::G) -> Self {
        Self { prev, next }
    }

    fn prev(&self) -> &Self::G {
        &self.prev
    }

    fn next(&self) -> &Self::G {
        &self.next
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

impl VerifiableConsecutiveOnewayFunction for MockVCOF {
    type Witness = ChannelWitness<Ed25519>;
    type PrivateData = MockVcofPrivateData;
    type PublicData = MockVcofPublicData;
    type Proof = MockVcofProof;
    type Context = ();

    fn compute_next(
        &self,
        update_count: u64,
        _: &ChannelWitness<Ed25519>,
        _ctx: &Self::Context,
    ) -> Result<ChannelWitness<Ed25519>, ProvingError> {
        // Compute next as H(seed_pub || update_count)
        let next = self.witness_i(update_count);
        let next = ChannelWitness::try_from_snark_scalar(next).unwrap();
        Ok(next)
    }

    fn create_proof(
        &self,
        index: u64,
        _: &Self::PrivateData,
        _: &Self::PublicData,
        _: &Self::Context,
    ) -> Result<Self::Proof, ProvingError> {
        let proof = MockVcofProof { vcof: self.clone(), index };
        Ok(proof)
    }

    fn verify(
        &self,
        update_count: u64,
        public: &Self::PublicData,
        proof: &Self::Proof,
        _: &Self::Context,
    ) -> Result<(), InvalidProof> {
        if update_count < 1 {
            return Err(update_count.into());
        }

        if proof.index != update_count {
            return Err(update_count.into());
        }

        let prev = public.prev().as_xmr_point();
        if update_count == 1 {
            if *prev != self.seed_pub {
                return Err(update_count.into());
            }
        } else {
            let expected_prev = self.witness_i(update_count - 1);
            let expected_prev_pub = Ed25519::generator() * expected_prev;

            if expected_prev_pub != *prev {
                return Err(update_count.into());
            }
        }
        let expected_next = self.witness_i(update_count);
        let expected_next_pub = Ed25519::generator() * expected_next;

        let next = public.next().as_xmr_point();
        if expected_next_pub != *next {
            return Err(update_count.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::witness::Offset;
    use crate::cryptography::ChannelWitness;

    #[test]
    fn test_mock_vcof_consecutiveness() {
        // Create initial seed
        let seed = ChannelWitness::random();
        let pub0 = Ed25519::generator() * seed.offset();

        let vcof = MockVCOF::new(pub0);

        let (proof1, pub1) = vcof.next(1, &seed, &()).unwrap();
        // Verify first transition
        vcof.verify(1, &pub1, &proof1, &()).unwrap();

        // Compute the witness for index 1 to use as prev for next call
        let witness1 = ChannelWitness::try_from_snark_scalar(vcof.witness_i(1)).unwrap();

        // Advance again
        let (proof2, pub2) = vcof.next(2, &witness1, &()).unwrap();
        assert_eq!(*pub2.prev(), *pub1.next());
        vcof.verify(2, &pub2, &proof2, &()).unwrap();
    }

    #[test]
    fn test_mock_vcof_invalid_proof() {
        let seed = ChannelWitness::random();
        let pub0 = Ed25519::generator() * seed.offset();
        let vcof = MockVCOF::new(pub0);

        let (proof1, pub1) = vcof.next(1, &seed, &()).unwrap();

        // Create a proof with wrong index
        let bad_proof = MockVcofProof { vcof: vcof.clone(), index: 999 };
        let result = vcof.verify(1, &pub1, &bad_proof, &());
        assert_eq!(result, Err(InvalidProof::new(1)));

        // Verify with wrong update_count
        let result = vcof.verify(2, &pub1, &proof1, &());
        assert_eq!(result, Err(InvalidProof::new(2)));
    }
}
