use crate::monero::data_objects::MultisigSplitSecrets;
use hex::FromHexError;
use serde::{Deserialize, Serialize};

/// A curve-agnostic representation of a scalar.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GenericScalar(
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::array_from_hex")] [u8; 32],
);

/// A curve-agnostic representation of a point.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GenericPoint(
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::array_from_hex")] [u8; 32],
);

impl GenericPoint {
    /// Convert a hex-encoded string to a GenericPoint.
    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes)?;
        Ok(Self(bytes))
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
#[allow(non_snake_case)]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Comm0PublicOutputs {
    /// **Τ₀** - The public key/curve point on Baby Jubjub for ω₀.
    pub T_0: GenericPoint,
    /// **c₁** - Feldman commitment 1 (used in tandem with Feldman commitment 0 = Τ₀), which is a public key/curve point on Baby Jubjub.
    pub c_1: GenericPoint,
    /// **Φ₁** - The ephemeral public key/curve point on Baby Jubjub for message transportation to the peer.
    pub phi_1: GenericPoint,
    /// **χ₁** - The encrypted value of σ₁.
    pub enc_1: GenericScalar,
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
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Comm0PrivateOutputs {
    /// **ω₀** - The root private key protecting access to the user's locked value (witness₀).
    pub witness_0: GenericScalar,
    /// **σ₁** - The split of ω₀ shared with the peer (share₁).
    pub peer_share: GenericScalar,
    /// **σ₂** - The split of ω₀ shared with the KES (share₂).
    pub kes_share: GenericScalar,
    /// **Δ_BabyJubjub** - Optimization parameter (response_div_BabyJubjub).
    pub delta_bjj: GenericScalar,
    /// **Δ_Ed25519** - Optimization parameter (response_div_BabyJubJub).
    pub delta_ed: GenericScalar,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize)]
pub struct InitialProofsResult {
    pub public_outputs: Comm0PublicOutputs,
    pub private_outputs: Comm0PrivateOutputs,
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
