use crate::cryptography::dleq::Dleq;
use crate::cryptography::noir_prover::{InputConverter, NoirProver};
use crate::cryptography::vcof::{
    InvalidProof, NextWitness, ProvingError, VcofPrivateData, VcofPublicData, VerifiableConsecutiveOnewayFunction,
};
use crate::cryptography::vcof_impls::{NoirUpdateCircuit, PoseidonGrumpkinWitness};
use crate::cryptography::witness::{AsXmrPoint, ChannelWitnessPublic, Offset};
use crate::cryptography::ChannelWitness;
use crate::error::ReadError;
use crate::grease_protocol::utils::Readable;
use ciphersuite::{Ciphersuite, Ed25519};
use digest::Mac;
use grease_grumpkin::Grumpkin;
use log::warn;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use rand_core::OsRng;
use std::io::{Read, Write};
use std::marker::PhantomData;
use zeroize::Zeroize;
use zkuh_rs::noir_api::ProgramArtifact;

/// A VCOF prover for a ZK-SNARK+DLEQ construction using the Grumpkin curve and Poseidon hash.
pub type GP2VcofProver<'p> = SnarkDleqVcofProver<'p, Grumpkin, PoseidonGrumpkinWitness, NoirUpdateCircuit>;

/// A VCOF proof using Snark+DLEQ consists of the ZK-SNARK, _plus_ a DLEQ proof to link the SNARK-friendly curve and Ed25519.
pub struct SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    /// A proof that $P_i, T_i$ correspond such that
    /// $P_i = w_i \cdot G^E$ (Ed25519) and $T_i = w_i \cdot G^{SF}$ (SNARK-friendly curve)
    dleq: <Ed25519 as Dleq<SF>>::Proof,
    /// A SNARK proving that $w_{i+1} = H(update_count, w_i)$, $T_i = w_i \cdot G$ and $T_{i+1} = w_{i+1} \cdot G$.
    snark: Vec<u8>,
}

impl<SF> Readable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let dleq =
            <Ed25519 as Dleq<SF>>::read(reader).map_err(|e| ReadError::new("SnarkDleqProof", format!("DLEQ: {e}")))?;
        let snark_len =
            reader.read_u64().map_err(|e| ReadError::new("SnarkDleqProof", format!("SNARK length: {e}")))?;
        let mut snark = vec![0u8; snark_len as usize];
        reader.read_exact(&mut snark).map_err(|e| ReadError::new("SnarkDleqProof", format!("SNARK data: {e}")))?;
        Ok(Self { dleq, snark })
    }
}

impl<SF> Writable for SnarkDleqProof<SF>
where
    SF: Curve,
    Ed25519: Dleq<SF>,
{
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.dleq.write(writer)?;
        writer.emit_u64(self.snark.len() as u64)?;
        writer.write_all(&self.snark)
    }
}

/// A Verifiable Consecutive Oneway Function (VCOF) implementation using SNARKs the KeyUpdate function with a DLEQ
/// proof to prove equivalence between the SNARK-friendly curve (SF) and Ed25519.
pub struct SnarkDleqVcofProver<'p, SF, F, C: InputConverter> {
    next_witness: F,
    noir_prover: NoirProver<'p, C>,
    _snark_curve: PhantomData<SF>,
}

impl<'p, SF, V, C> SnarkDleqVcofProver<'p, SF, V, C>
where
    V: NextWitness<W = ChannelWitness<SF>>,
    SF: Curve,
    Ed25519: Dleq<SF>,
    C: InputConverter,
{
    pub fn new(
        checksum: impl Into<String>,
        program: &'p ProgramArtifact,
        converter: &'p C,
    ) -> Result<Self, ProvingError> {
        let noir_prover = NoirProver::new(checksum, program, converter)
            .map_err(|e| ProvingError::init_err(format!("NoirProver initialization error: {e}")))?;
        Ok(Self { next_witness: V::default(), noir_prover, _snark_curve: PhantomData })
    }
}

impl<'p, SF, V, C> VerifiableConsecutiveOnewayFunction for SnarkDleqVcofProver<'p, SF, V, C>
where
    V: NextWitness<W = ChannelWitness<SF>>,
    SF: Curve,
    Ed25519: Dleq<SF>,
    C: InputConverter<Private = SnarkDleqPrivateData<SF>, Public = SnarkDleqPublicData<SF>>,
{
    type Witness = ChannelWitness<SF>;
    type PrivateData = SnarkDleqPrivateData<SF>;
    type PublicData = SnarkDleqPublicData<SF>;
    type Proof = SnarkDleqProof<SF>;
    type Context = ();

    fn compute_next(
        &self,
        update_count: u64,
        prev: &Self::Witness,
        _: &Self::Context,
    ) -> Result<Self::Witness, ProvingError> {
        let result =
            self.next_witness.next_witness(update_count, prev).map_err(|e| ProvingError::derive_err(e.to_string()))?;
        Ok(result)
    }

    fn create_proof(
        &self,
        index: u64,
        private_input: &Self::PrivateData,
        public_input: &Self::PublicData,
        _ctx: &Self::Context,
    ) -> Result<Self::Proof, ProvingError> {
        // generate the DLEQ proof
        let mut rng = OsRng;
        let secret = *private_input.next().offset();
        let (dleq, (_x, _y)) = <Ed25519 as Dleq<SF>>::generate_dleq(&mut rng, secret)
            .map_err(|e| ProvingError::prove_err(format!("DLEQ generation error: {}", e)))?;
        // generate the ZK-SNARK proof
        let snark = self
            .noir_prover
            .prove(index, private_input, public_input)
            .map_err(|e| ProvingError::prove_err(format!("NoirProver proof error: {e}")))?;
        // combine into SnarkDleqProof
        Ok(SnarkDleqProof { dleq, snark })
    }

    fn verify(
        &self,
        i: u64,
        public_in: &Self::PublicData,
        proof: &Self::Proof,
        _: &Self::Context,
    ) -> Result<(), InvalidProof> {
        // Verify the DLEQ proof
        let dleq_proof = &proof.dleq;
        let ed_point = public_in.next().as_xmr_point();
        let snark_point = public_in.next().snark_point();
        Ed25519::verify_dleq(dleq_proof, ed_point, snark_point).map_err(|e| {
            warn!("DLEQ verification failed: {e}");
            InvalidProof::new(i)
        })?;
        // Verify the SNARK proof
        let snark_proof = &proof.snark;
        self.noir_prover.verify(i, public_in, snark_proof).map_err(|e| {
            warn!("SNARK verification failed: {e}");
            InvalidProof::new(i)
        })?;
        Ok(())
    }
}

#[derive(Clone, Debug, Zeroize)]
pub struct SnarkDleqPrivateData<SF: Ciphersuite> {
    prev: ChannelWitness<SF>,
    next: ChannelWitness<SF>,
}

impl<SF: Ciphersuite> VcofPrivateData for SnarkDleqPrivateData<SF> {
    type W = ChannelWitness<SF>;

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
pub struct SnarkDleqPublicData<SF: Ciphersuite> {
    prev: ChannelWitnessPublic<SF>,
    next: ChannelWitnessPublic<SF>,
}

impl<SF: Ciphersuite> VcofPublicData for SnarkDleqPublicData<SF> {
    type G = ChannelWitnessPublic<SF>;

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

#[cfg(test)]
mod tests {
    use crate::cryptography::vcof::{NextWitness, VcofPublicData};
    use crate::cryptography::vcof::VerifiableConsecutiveOnewayFunction;
    use crate::cryptography::vcof_impls::PoseidonGrumpkinWitness;
    use crate::cryptography::vcof_impls::{NoirUpdateCircuit, CHECKSUM_UPDATE};
    use crate::cryptography::vcof_snark_dleq::GP2VcofProver;
    use crate::cryptography::witness::{AsXmrPoint, Offset};
    use crate::cryptography::ChannelWitness;
    use crate::helpers::xmr_scalar_as_be_hex;
    use ciphersuite::group::GroupEncoding;
    use grease_grumpkin::Grumpkin;
    use grease_grumpkin::{ArkPrimeField, BigInteger};
    use log::info;

    #[test]
    fn update_circuit_noir_matches_rust_implementation() {
        env_logger::try_init().ok();
        // Load the circuit artifact
        let circuit = NoirUpdateCircuit::new().expect("Failed to load NoirUpdateCircuit artifact");
        let prover =
            GP2VcofProver::new(CHECKSUM_UPDATE, circuit.artifact(), &circuit).expect("Failed to create NoirProver");
        // Use the known data from Prover.toml (big-endian hex)
        let scalar_be = hex::decode("004ed0099c91f5472632e7c5ff692f3ef438a3a4d2c1a08f025e931bb708d983").unwrap();
        let w0 = ChannelWitness::<Grumpkin>::try_from_be_bytes(&scalar_be.try_into().unwrap())
            .expect("Failed to create witness from Prover.toml scalar");
        let w0_public = w0.public_points();
        // Log the public points for the transition
        let (x, y) = w0_public.snark_point().as_coordinates_be();
        // Verify point coordinates match Prover.toml
        assert_eq!(
            x, "07052091e5e2778b8da8fba45ac11ee22daeee1c4d0ff93ba741b1e4349a6eff",
            "pub_prev.x mismatch"
        );
        assert_eq!(
            y, "0a6bfe2e7a9c55b01e4c3dd29a93aabb1b68e21d449ebf184010ddd087e2068e",
            "pub_prev.y mismatch"
        );

        // Compute next witness manually to verify
        let next_witness_fn = PoseidonGrumpkinWitness;
        let w1 = next_witness_fn.next_witness(1, &w0).expect("Failed to compute next witness");
        let w1_public = w1.public_points();

        let w1_hex = xmr_scalar_as_be_hex(w1.offset());
        assert_eq!(
            w1_hex, "024f1d193ceff6131819b6da4b541b8d29fcef2d8981eba79116d075240d8c58",
            "w1 mismatch"
        );
        let (p1x, p1y) = w1_public.snark_point().as_coordinates_be();
        assert_eq!(p1x, "04e0f6f4f79db6fc119fc681e9d9319760e9f30ad963e499601e3b10bc876013");
        assert_eq!(p1y, "1d7570ee391669cd88727a40aaa528d8b0aee3cf2918e888fb0a2fed72a72626");

        // Generate a proof for the transition from w0 to w1 (update_count = 1)
        let (proof, public_data) = prover.next(1, &w0, &()).expect("Failed to generate proof");

        info!("SNARK proof size: {} bytes", proof.snark.len());
        info!("VCOF proof generated successfully!");

        let (c1x, c1y) = public_data.next().snark_point().as_coordinates_be();
        assert_eq!(c1x, p1x, "public_data.next x coordinate mismatch");
        assert_eq!(c1y, p1y, "public_data.next y coordinate mismatch");

        prover.verify(1, &public_data, &proof, &()).expect("proof to verify");
        assert!(prover.verify(2, &public_data, &proof, &()).is_err());
    }
}
