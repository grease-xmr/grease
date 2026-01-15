use crate::cryptography::common_types::HashCommitment256;
use crate::cryptography::Commit;
use crate::grease_protocol::utils::write_field_element;
use crate::monero::data_objects::MultisigSplitSecrets;
use crate::XmrScalar;
use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::GroupEncoding;
use curve25519_dalek::{EdwardsPoint, Scalar};
use flexible_transcript::{DigestTranscript, SecureDigest, Transcript};
use hex::FromHexError;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use monero::consensus::WriteExt;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The public inputs to the ZK prover for the initial witness generation proof. These parameters are shared with the
/// peer and are publicly known.
#[expect(non_snake_case)]
#[derive(Clone, Debug)]
pub struct PublicInputs<C: Curve> {
    /// The public key/curve point on the ZK curve for the KES
    pub kes_point: C::G,
    /// The public key/curve point on the ZK curve for the peer
    pub my_pubkey: C::G,
    /// Random field element on the ZK curve, used as a nonce (𝛎_peer)
    pub nonce_peer: C::F,
    /// The public key/curve point on the ZK curve for ω₀ (T₀)
    pub T0: C::G,
    /// The Fiat–Shamir heuristic challenge response on the ZK curve
    pub rho_zk: C::F,
    /// The public key/curve point on Ed25519 for ω₀ (S₀)
    pub S0: EdwardsPoint,
    ///  The Fiat–Shamir heuristic challenge response on the Ed25519 curve
    pub rho_ed: Scalar,
}

impl<C: Curve, D: SecureDigest + Send + Clone> Commit<D> for PublicInputs<C> {
    type Committed = HashCommitment256<D>;
    type Transcript = DigestTranscript<D>;

    fn commit(&self) -> Self::Committed {
        let mut transcript = Self::Transcript::new(b"public-input-commitment");
        transcript.append_message(b"kes_point", self.kes_point.to_bytes());
        transcript.append_message(b"my_pubkey", self.my_pubkey.to_bytes());
        transcript.append_message(b"nonce_peer", self.nonce_peer.to_repr());
        transcript.append_message(b"T0", self.T0.to_bytes());
        transcript.append_message(b"rho_zk", self.rho_zk.to_repr());
        transcript.append_message(b"S0", self.S0.compress().to_bytes());
        transcript.append_message(b"rho_ed", self.rho_ed.to_bytes());

        let commitment = transcript.challenge(b"public-input");
        let mut data = [0u8; 32];
        // The compiler guarantees that the output size of the hash function is at least 32 bytes.
        data.copy_from_slice(&commitment[0..32]);
        HashCommitment256::new(data)
    }

    fn verify(&self, expected: &Self::Committed) -> bool {
        let actual_commitment = self.commit();
        actual_commitment == *expected
    }
}

impl<C: Curve> Writable for PublicInputs<C> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        crate::grease_protocol::utils::write_group_element::<C, W>(writer, &self.kes_point)?;
        crate::grease_protocol::utils::write_group_element::<C, W>(writer, &self.my_pubkey)?;
        crate::grease_protocol::utils::write_group_element::<C, W>(writer, &self.T0)?;
        crate::grease_protocol::utils::write_field_element::<C, W>(writer, &self.rho_zk)?;
        crate::grease_protocol::utils::write_field_element::<C, W>(writer, &self.nonce_peer)?;
        writer.emit_slice(&self.S0.to_bytes())?;
        writer.emit_slice(&self.rho_ed.to_bytes())?;
        Ok(())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateNonces<C: Curve> {
    /// 𝛎_ꞷ0 - Random blinding value
    pub random_blinding: C::F,
    /// Random value
    pub a1: C::F,
    /// 𝛎_1 - Random value
    pub r1: C::F,
    /// 𝛎_2 - Random value
    pub r2: C::F,
    /// 𝛎_DLEQ - Random blinding value for DLEQ proof
    pub blinding_dleq: C::F,
}

impl<C: Curve> PrivateNonces<C> {
    pub fn new_random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let random_blinding = C::random_nonzero_F(rng);
        let a1 = C::random_nonzero_F(rng);
        let r1 = C::random_nonzero_F(rng);
        let r2 = C::random_nonzero_F(rng);
        let blinding_dleq = C::random_nonzero_F(rng);
        Self { random_blinding, a1, r1, r2, blinding_dleq }
    }
}

impl<C: Curve> Writable for PrivateNonces<C> {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        write_field_element::<C, W>(writer, &self.random_blinding)?;
        write_field_element::<C, W>(writer, &self.a1)?;
        write_field_element::<C, W>(writer, &self.r1)?;
        write_field_element::<C, W>(writer, &self.r2)?;
        write_field_element::<C, W>(writer, &self.blinding_dleq)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::PublicInputs;
    use crate::cryptography::common_types::HashCommitment256;
    use crate::cryptography::Commit;
    use blake2::Blake2b512;
    use ciphersuite::group::ff::Field;
    use ciphersuite::{Ciphersuite, Secp256k1};
    use dalek_ff_group::{EdwardsPoint, Scalar};
    use hex::{FromHex, ToHex};
    use modular_frost::curve::Ed25519;
    use modular_frost::curve::Group;
    use rand_core::{OsRng, RngCore};
    use sha3::Sha3_256;

    #[test]
    fn test_hash_commitment() {
        let inputs = PublicInputs::<Ed25519> {
            kes_point: Ed25519::generator(),
            my_pubkey: Ed25519::generator(),
            nonce_peer: Scalar::from(1u8),
            T0: Ed25519::generator(),
            rho_zk: Scalar::from(1u8),
            S0: Ed25519::generator().0,
            rho_ed: Scalar::from(1u8).0,
        };

        let commitment = <PublicInputs<Ed25519> as Commit<Blake2b512>>::commit(&inputs);
        let commit_str = commitment.encode_hex::<String>();
        assert_eq!(commit_str, "2044b655d502d671dae78f2ff9c56bf218c39b7a62f466e603f48d3961bd299f");

        // When decoding, you need to specify which hash function created the hash!
        let decoded = HashCommitment256::<Blake2b512>::from_hex(&commit_str).expect("Failed to decode commitment");
        assert_eq!(commitment, decoded);
        // ...and it will verify correctly
        assert!(inputs.verify(&decoded));

        // You could erroneously decode it as if it were created with a different hash function...
        let decoded_wrong = HashCommitment256::<Sha3_256>::from_hex(&commit_str)
            .expect("Failed to decode commitment with wrong hash function");

        // ...But it wouldn't verify correctly.
        assert!(!inputs.verify(&decoded_wrong));
    }

    #[test]
    fn test_commitment_ed25519() {
        fn random_point() -> EdwardsPoint {
            EdwardsPoint::random(OsRng)
        }

        fn random_scalar() -> Scalar {
            Scalar::random(&mut OsRng)
        }

        let mut public_inputs = PublicInputs::<Ed25519> {
            kes_point: random_point(),
            my_pubkey: random_point(),
            nonce_peer: random_scalar(),
            T0: random_point(),
            rho_zk: random_scalar(),
            S0: random_point().0,
            rho_ed: random_scalar().0,
        };

        let commitment = <PublicInputs<Ed25519> as Commit<Blake2b512>>::commit(&public_inputs);
        assert!(public_inputs.verify(&commitment));

        // Modify public inputs and ensure verification fails
        public_inputs.nonce_peer = random_scalar();
        assert!(!public_inputs.verify(&commitment));

        // You can use different hash algorithms, easy peasy.
        let commitment2 = <PublicInputs<Ed25519> as Commit<Sha3_256>>::commit(&public_inputs);
        assert!(public_inputs.verify(&commitment2));

        public_inputs.nonce_peer = random_scalar();
        assert!(!public_inputs.verify(&commitment2));

        // The compiler won't even let you compare commitments made from different hash algorithms!
        // assert!(commitment != commitment2);
    }

    /// It's simple to create PublicInputs for different curves, as long as they implement the Ciphersuite trait.
    /// Here we do it for SecP256k1, which is used in Bitcoin and Ethereum.
    /// Note that the Ed25519 points and scalars are still used for S0 and rho_ed, as those always refer to Monero.
    #[test]
    fn test_commitment_secp256k1() {
        fn random_k256_point() -> <Secp256k1 as Ciphersuite>::G {
            let p = random_k256_scalar();
            <Secp256k1 as Ciphersuite>::generator() * p
        }

        fn random_k256_scalar() -> <Secp256k1 as Ciphersuite>::F {
            let mut bytes = [0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            Secp256k1::hash_to_F(b"secp256k1", &bytes)
        }

        let mut public_inputs = PublicInputs::<Secp256k1> {
            kes_point: random_k256_point(),
            my_pubkey: random_k256_point(),
            nonce_peer: random_k256_scalar(),
            T0: random_k256_point(),
            rho_zk: random_k256_scalar(),
            S0: EdwardsPoint::random(OsRng).0,
            rho_ed: Scalar::random(&mut OsRng).0,
        };

        let commitment = <PublicInputs<Secp256k1> as Commit<Blake2b512>>::commit(&public_inputs);
        assert!(public_inputs.verify(&commitment));

        // Modify public inputs and ensure verification fails
        public_inputs.nonce_peer = random_k256_scalar();
        assert!(!public_inputs.verify(&commitment));

        // You can use different hash algorithms, easy peasy.
        let commitment2 = <PublicInputs<Secp256k1> as Commit<Sha3_256>>::commit(&public_inputs);
        assert!(public_inputs.verify(&commitment2));

        public_inputs.nonce_peer = random_k256_scalar();
        assert!(!public_inputs.verify(&commitment2));
    }
}
//----------------------------------- Legacy types -----------------------------------//
/// A curve-agnostic representation of a scalar.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct GenericScalar(
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::array_from_hex")]
    pub  [u8; 32],
);

impl GenericScalar {
    /// Create a new GenericScalar from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        GenericScalar(bytes)
    }
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        GenericScalar(random_256_bits(rng))
    }
}

/// A curve-agnostic representation of a point.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
pub struct GenericPoint(
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::array_from_hex")] [u8; 32],
);

impl GenericPoint {
    /// Create a new GenericPoint from a 32-byte array.
    pub fn new(bytes: [u8; 32]) -> Self {
        GenericPoint(bytes)
    }

    /// Convert a hex-encoded string to a GenericPoint.
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        GenericPoint(random_256_bits(rng))
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Comm0PrivateInputs {
    /// 𝛎_ꞷ0 - Random blinding value
    pub random_blinding: GenericScalar,
    /// Random value
    pub a1: GenericPoint,
    /// 𝛎_1 - Random value
    pub r1: GenericPoint,
    /// 𝛎_2 - Random value
    pub r2: GenericPoint,
    /// 𝛎_DLEQ - Random blinding value for DLEQ proof
    pub blinding_dleq: GenericScalar,
}

/// The outputs of the Commitment0 proofs that must be shared with the peer.
#[expect(non_snake_case)]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Comm0PublicOutputs {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub T_0: GenericPoint,
    /// **Φ₂** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the KES.
    pub phi_2: GenericPoint,
    /// **χ₂** - The encrypted value of σ₂ (enc₂).
    pub enc_2: GenericScalar,
    /// **S₀** - The public key/curve point on Ed25519 for ω₀.
    pub S_0: GenericPoint,
    /// **c** - The Fiat–Shamir heuristic challenge (challenge_bytes).
    pub c: GenericScalar,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (response_BabyJubJub).
    pub rho_bjj: GenericScalar,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (response_div_ed25519).
    pub rho_ed: GenericScalar,
}

/// The proof outputs that are stored, but not shared with the peer.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Comm0PrivateOutputs {
    /// **ω₀** - The root private key protecting access to the user's locked value (witness₀).
    #[serde(
        serialize_with = "crate::helpers::xmr_scalar_to_hex",
        deserialize_with = "crate::helpers::xmr_scalar_from_hex"
    )]
    pub witness_0: XmrScalar,
    /// **Δ_BabyJubjub** - Optimization parameter (response_div_BabyJubjub).
    pub delta_bjj: GenericScalar,
    /// **Δ_Ed25519** - Optimization parameter (response_div_BabyJubJub).
    pub delta_ed: GenericScalar,
}

/// Struct holding the public outputs from a ZK update proof.
#[expect(non_snake_case)]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PublicUpdateOutputs {
    /// **Τ_(i-1)** - The public key/curve point on Baby Jubjub for ω_(i-1).
    pub T_prev: GenericPoint,
    /// **Τ_i** - The public key/curve point on Baby Jubjub for ω_i.
    pub T_current: GenericPoint,
    /// **S_i** - The public key/curve point on Ed25519 for ω_i.
    pub S_current: GenericPoint,
    /// **C** - The Fiat–Shamir heuristic challenge (`challenge_bytes`).
    pub challenge: GenericScalar,
    /// **ρ_BabyJubjub** - The Fiat–Shamir heuristic challenge response on the Baby Jubjub curve (`response_BabyJubJub`).
    pub rho_bjj: GenericScalar,
    /// **ρ_Ed25519** - The Fiat–Shamir heuristic challenge response on the Ed25519 curve (`response_div_ed25519`).
    pub rho_ed: GenericScalar,
    /// **R_BabyJubjub** - DLEQ commitment 1, which is a public key/curve point on Baby Jubjub (`R_1`).
    pub R_bjj: GenericPoint,
    /// **R_Ed25519** - DLEQ commitment 2, which is a public key/curve point on Ed25519 (`R_2`).
    pub R_ed: GenericPoint,
}

/// Struct representing private variables.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivateUpdateOutputs {
    /// The ith update index. The initial commitment is update 0.
    pub update_count: u64,
    /// **ω_i** - The next private key protecting access to close the payment channel (`witness_i`).
    #[serde(
        serialize_with = "crate::helpers::xmr_scalar_to_hex",
        deserialize_with = "crate::helpers::xmr_scalar_from_hex"
    )]
    pub witness_i: XmrScalar,
    /// **Δ_BabyJubjub** - Optimization parameter (`response_div_BabyJubjub`).
    pub delta_bjj: GenericScalar,
    /// **Δ_Ed25519** - Optimization parameter (`response_div_BabyJubJub`).
    pub delta_ed: GenericScalar,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proofs0 {
    pub public_outputs: Comm0PublicOutputs,
    pub private_outputs: Comm0PrivateOutputs,
    pub proofs: Vec<u8>,
}

impl Proofs0 {
    pub fn public_only(&self) -> PublicProof0 {
        PublicProof0 { public_outputs: self.public_outputs.clone(), proofs: self.proofs.clone() }
    }
}

/// The output of the ZK proof for a channel update.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateProofs {
    pub public_outputs: PublicUpdateOutputs,
    pub private_outputs: PrivateUpdateOutputs,
    pub proof: Vec<u8>,
}

impl UpdateProofs {
    /// Convert the proof to a public proof.
    pub fn public_only(&self) -> PublicUpdateProof {
        PublicUpdateProof { public_outputs: self.public_outputs.clone(), proof: self.proof.clone() }
    }
}

/// The output of the ZK proof for a channel update.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PublicUpdateProof {
    pub public_outputs: PublicUpdateOutputs,
    pub proof: Vec<u8>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct PublicProof0 {
    pub public_outputs: Comm0PublicOutputs,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    pub proofs: Vec<u8>,
}

/// A representation of proof that the merchant has established the KES correctly using the shared secrets and the
/// agreed KES public key.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct KesProof {
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEncryptedKey(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    pub my_shards: MultisigSplitSecrets,
    pub their_shards: MultisigSplitSecrets,
}

pub fn generate_txc0_nonces<R: CryptoRng + RngCore>(rng: &mut R) -> Comm0PrivateInputs {
    Comm0PrivateInputs {
        random_blinding: GenericScalar::random(rng),
        a1: GenericPoint::random(rng),
        r1: GenericPoint::random(rng),
        r2: GenericPoint::random(rng),
        blinding_dleq: GenericScalar::random(rng),
    }
}

pub fn random_256_bits<R: CryptoRng + RngCore>(rng: &mut R) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}
