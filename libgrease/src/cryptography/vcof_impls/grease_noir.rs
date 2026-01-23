//! Noir circuit integration for Grease payment channel state updates.
//!
//! This module provides the interface between Grease's payment channel state machine
//! and Noir zero-knowledge circuits. It handles:
//!
//! - Loading compiled Noir circuit artifacts (ACIR bytecode)
//! - Converting Grumpkin curve points and scalars to Noir-compatible input formats
//! - Implementing the [`InputConverter`] trait for proof generation
//!
//! # Circuit Architecture
//!
//! The `GreaseUpdate` circuit proves correct state transitions in a payment channel.
//! Each update proves knowledge of a secret witness `wn_prev` such that the transition
//! from `pub_prev` to `pub_next` is valid according to the VCOF (Verifiable Consecutive
//! Oneway Function) construction.
//!
//! # Curve Relationships
//!
//! This module exploits the BN254/Grumpkin cycle curve relationship:
//! - Grumpkin's base field (Fq) equals BN254's scalar field (Fr)
//! - This allows direct field element reinterpretation without expensive conversions

use std::sync::LazyLock;

use acir_field::{AcirField, FieldElement};
use ciphersuite::group::ff::PrimeField;
use grease_grumpkin::{ArkPrimeField, BigInteger, Grumpkin, Point, Scalar};
use zkuh_rs::noir_api::artifacts::load_artifact_from_string;
use zkuh_rs::noir_api::{InputError, Inputs, PointInput, ProgramArtifact};

use crate::cryptography::noir_prover::InputConverter;
use crate::cryptography::vcof::{VcofPrivateData, VcofPublicData};
use crate::cryptography::vcof_snark_dleq::{SnarkDleqPrivateData, SnarkDleqPublicData};
use crate::cryptography::witness::ChannelWitnessPublic;

// Commented out: GreaseInit circuit constants (not yet implemented)
// pub const CHECKSUM_INIT: &str = "1234bcd";
// pub const PATH_INIT: &str = include_str!("../../../../circuits/target/GreaseInit.json");

/// SHA256 checksum of the `GreaseUpdate` circuit bytecode.
///
/// Used to verify circuit integrity and ensure the correct circuit version is loaded.
/// Should be updated whenever the circuit is recompiled.
//pub const CHECKSUM_UPDATE: &str = "d7c7752942b745dc0f408ecd781d1983a67df0a7e602cfa64e08a33323bc5144c2424ae9d7a3e3d8b3d84b53758c0eede204623ca404b91eb8e7ec30fed6874d";
pub const CHECKSUM_UPDATE: &str = "8b1f86e5a15b5dbd2a49d8986ffb0681ca58b52d51eadee1f67a553ebd32ff428273925a0a8d21d94621309ce13d68b18638ec7ab266c34074db517efad6840f";

/// Embedded JSON artifact for the `GreaseUpdate` Noir circuit.
///
/// The artifact is compiled from the Noir source and contains:
/// - ACIR bytecode for the circuit
/// - ABI definitions for input/output parameters
/// - Debug information (if compiled with debug flags)
///
/// Embedded at compile time via `include_str!` for zero-cost runtime loading.
pub const PATH_UPDATE: &str = include_str!("../../../../circuits/target/GreaseUpdate.json");

/// Global lazy-loaded instance of [`NoirUpdateCircuit`].
///
/// Initialized on first access. If loading fails, the process will panic with
/// an error message describing the failure.
///
/// # Panics
///
/// Panics if the embedded circuit artifact cannot be parsed. This indicates
/// a build configuration error (missing or corrupted circuit JSON).
pub static NOIR_UPDATE_CIRCUIT: LazyLock<NoirUpdateCircuit> =
    LazyLock::new(|| NoirUpdateCircuit::new().expect("Failed to load NoirUpdateCircuit artifact"));

/// Wrapper around the compiled `GreaseUpdate` Noir circuit artifact.
///
/// This struct loads and holds the ACIR bytecode and ABI for the circuit,
/// providing methods to access the artifact and convert domain types to
/// circuit inputs.
///
/// # Usage
///
/// Prefer using the global [`NOIR_UPDATE_CIRCUIT`] static rather than
/// constructing new instances, as loading the artifact has overhead.
///
/// ```ignore
/// use crate::cryptography::vcof_impls::NOIR_UPDATE_CIRCUIT;
///
/// let artifact = NOIR_UPDATE_CIRCUIT.artifact();
/// ```
pub struct NoirUpdateCircuit {
    /// The parsed Noir program artifact containing ACIR bytecode and ABI.
    pub artifact: ProgramArtifact,
}

impl NoirUpdateCircuit {
    /// Creates a new [`NoirUpdateCircuit`] by parsing the embedded artifact JSON.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the embedded JSON artifact cannot be parsed.
    /// This typically indicates a corrupted build artifact.
    pub fn new() -> Result<Self, std::io::Error> {
        let artifact = load_artifact_from_string(PATH_UPDATE)?;
        Ok(Self { artifact })
    }

    /// Returns a reference to the underlying [`ProgramArtifact`].
    ///
    /// The artifact contains the ACIR bytecode needed by the prover backend
    /// and the ABI for encoding/decoding circuit inputs and outputs.
    pub fn artifact(&self) -> &ProgramArtifact {
        &self.artifact
    }
}

/// [`InputConverter`] implementation for the `GreaseUpdate` circuit.
///
/// Converts Grease domain types ([`SnarkDleqPrivateData`] and [`SnarkDleqPublicData`])
/// into the Noir circuit's expected input format.
///
/// # Circuit Input Structure
///
/// The `GreaseUpdate` circuit expects the following parameters:
///
/// | Name       | Type           | Visibility | Description                      |
/// |------------|----------------|------------|----------------------------------|
/// | `i`        | field          | public     | Update index (state counter)     |
/// | `wn_prev`  | field          | private    | Previous witness scalar          |
/// | `pub_prev` | Point {x, y}   | public     | Previous public commitment point |
/// | `pub_next` | Point {x, y}   | public     | Next public commitment point     |
///
/// # Example JSON Structure
///
/// ```json
/// {
///   "parameters": [
///     { "name": "i", "type": { "kind": "field" }, "visibility": "public" },
///     { "name": "wn_prev", "type": { "kind": "field" }, "visibility": "private" },
///     { "name": "pub_prev", "type": "PointStruct: {x, y}" },
///     { "name": "pub_next", "type": "PointStruct: {x, y}" }
///   ]
/// }
/// ```
impl InputConverter for NoirUpdateCircuit {
    type Private = SnarkDleqPrivateData<Grumpkin>;
    type Public = SnarkDleqPublicData<Grumpkin>;

    /// Converts private and public VCOF data into circuit inputs.
    ///
    /// # Arguments
    ///
    /// * `index` - The state update index (monotonically increasing counter)
    /// * `private` - The prover's secret witness data
    /// * `public` - The publicly verifiable commitment points
    ///
    /// # Errors
    ///
    /// Returns [`InputError`] if point conversion fails (e.g., invalid coordinates).
    fn to_inputs(&self, index: u64, private: &Self::Private, public: &Self::Public) -> Result<Inputs, InputError> {
        let wn_prev = scalar_to_be_bytes(private.prev().as_snark_scalar());
        let pub_prev = grumpkin_pt_to_point_input(public.prev());
        let pub_next = grumpkin_pt_to_point_input(public.next());
        let inputs = Inputs::new()
            .add_field("i", index)
            .add_field("wn_prev", wn_prev)
            .add("pub_prev", pub_prev)
            .map_err(|(_, e)| e)?
            .add("pub_next", pub_next)
            .map_err(|(_, e)| e)?;
        Ok(inputs)
    }
}

/// Converts a Grumpkin scalar (witness value) to big-endian bytes for Noir circuit input.
///
/// The `FieldInput::from([u8; 32])` implementation expects big-endian bytes, but
/// arkworks scalars serialize in little-endian format. This function handles the
/// conversion by extracting the scalar's bigint representation and converting to
/// big-endian byte order.
///
/// # Arguments
///
/// * `scalar` - A Grumpkin scalar (the witness value)
///
/// # Returns
///
/// A 32-byte big-endian representation suitable for `FieldInput::from([u8; 32])`.
fn scalar_to_be_bytes(scalar: grease_grumpkin::Scalar) -> [u8; 32] {
    scalar.0.into_bigint().to_bytes_be().try_into().expect("scalar is 32 bytes")
}

/// Converts a Grumpkin base field element (Fq) to a Noir [`FieldElement`] (BN254 Fr).
///
/// This exploits the BN254/Grumpkin cycle curve relationship where Grumpkin's base
/// field equals BN254's scalar field, allowing direct byte-level reinterpretation.
///
/// # Arguments
///
/// * `fq` - A Grumpkin base field element representing a point coordinate
///
/// # Returns
///
/// A [`FieldElement`] suitable for use as a Noir circuit input.
///
/// # Note
///
/// Uses `from_le_bytes_reduce` for safety, though reduction should never occur
/// since the fields have identical orders.
fn fq_to_field_element(fq: grease_grumpkin::Fq) -> FieldElement {
    let bytes = fq.into_bigint().to_bytes_le();
    FieldElement::from_le_bytes_reduce(&bytes)
}

/// Converts a [`ChannelWitnessPublic`] Grumpkin point to a Noir [`PointInput`].
///
/// Extracts the affine (x, y) coordinates from the witness's SNARK-compatible
/// point representation and converts each coordinate to a [`FieldElement`].
///
/// # Arguments
///
/// * `p` - A channel witness public point on the Grumpkin curve
///
/// # Returns
///
/// A [`PointInput`] struct containing the x and y coordinates as [`FieldElement`]s,
/// ready for use as a Noir circuit input.
fn grumpkin_pt_to_point_input(p: &ChannelWitnessPublic<Grumpkin>) -> PointInput {
    let affine: Point = (*p.snark_point()).into();
    PointInput { x: fq_to_field_element(affine.x), y: fq_to_field_element(affine.y), is_infinite: Some(false) }
}
