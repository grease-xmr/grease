use crate::cryptography::witness::Offset;
use crate::cryptography::{AsXmrPoint, ChannelWitness, ChannelWitnessPublic};
use crate::error::ReadError;
use crate::grease_protocol::utils::Readable;
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519, Secp256k1};
use dalek_ff_group::{EdwardsPoint as XmrPoint, EdwardsPoint, Scalar as XmrScalar};
use dleq::cross_group::{ConciseLinearDLEq, Generators};
use flexible_transcript::{RecommendedTranscript, Transcript};
use grease_babyjubjub::{BabyJubJub, BjjPoint};
use grease_grumpkin::{Grumpkin, GrumpkinPoint};
use k256::ProjectivePoint;
use modular_frost::algorithm::SchnorrSignature;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::io;
use std::io::{Read, Write};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone)]
pub struct EdSchnorrSignature(pub SchnorrSignature<Ed25519>);

impl EdSchnorrSignature {
    pub fn read<R: Read + ?Sized>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; 64];
        reader.read_exact(&mut buf)?;
        let sig = SchnorrSignature::<Ed25519>::read(&mut &buf[..])?;
        Ok(EdSchnorrSignature(sig))
    }
}

impl Writable for EdSchnorrSignature {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.0.write(writer)
    }
}

pub trait Dleq<SF: Curve>: Curve {
    type Proof: Clone + Writable;

    /// Generate a DLEQ proof from a channel witness.
    ///
    /// The `ChannelWitness<SF>` guarantees that the secret scalar is valid in both Ed25519 and SF's field,
    /// eliminating the possibility of field overflow errors.
    ///
    /// Returns the proof and the public points corresponding to the witness.
    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &ChannelWitness<SF>,
    ) -> Result<(Self::Proof, ChannelWitnessPublic<SF>), DleqError>;

    /// Verify that the provided proof shows that the discrete log of the Ed25519 point is the same as the discrete log
    /// of the SF curve point, AND that the prover possesses knowledge of both discrete logs.
    fn verify_dleq(proof: &Self::Proof, public_points: &ChannelWitnessPublic<SF>) -> Result<(), DleqError>;

    /// Read the proof from a reader
    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError>;
}

impl Dleq<Ed25519> for Ed25519 {
    type Proof = EdSchnorrSignature;

    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &ChannelWitness<Ed25519>,
    ) -> Result<(Self::Proof, ChannelWitnessPublic<Ed25519>), DleqError> {
        let secret = *witness.offset();
        let nonce = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut *rng);
        let nonce_pub = Ed25519::generator() * nonce;
        let public_point = Ed25519::generator() * secret;
        let challenge = ownership_challenge(&nonce_pub, &public_point);
        let mut zs = Zeroizing::new(secret);
        let proof = SchnorrSignature::sign(&zs, Zeroizing::new(nonce), challenge);
        zs.zeroize();
        Ok((EdSchnorrSignature(proof), witness.public_points()))
    }

    fn verify_dleq(proof: &Self::Proof, public_points: &ChannelWitnessPublic<Ed25519>) -> Result<(), DleqError> {
        // For Ed25519<>Ed25519, both points should be identical since they're on the same curve
        let valid = public_points.as_xmr_point().eq(public_points.snark_point()) && {
            let challenge = ownership_challenge(&proof.0.R, public_points.as_xmr_point());
            proof.0.verify(*public_points.as_xmr_point(), challenge)
        };
        match valid {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError> {
        let proof = EdSchnorrSignature::read(reader)?;
        Ok(proof)
    }
}

#[derive(Clone)]
pub struct DleqMoneroBjj(pub ConciseLinearDLEq<<Ed25519 as Ciphersuite>::G, <BabyJubJub as Ciphersuite>::G>);

impl DleqMoneroBjj {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let proof = ConciseLinearDLEq::<<Ed25519 as Ciphersuite>::G, <BabyJubJub as Ciphersuite>::G>::read(reader)?;
        Ok(DleqMoneroBjj(proof))
    }
}

impl Writable for DleqMoneroBjj {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.0.write(writer)
    }
}

impl Dleq<BabyJubJub> for Ed25519 {
    type Proof = DleqMoneroBjj;

    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &ChannelWitness<BabyJubJub>,
    ) -> Result<(Self::Proof, ChannelWitnessPublic<BabyJubJub>), DleqError> {
        let secret = *witness.offset();
        let mut transcript = RecommendedTranscript::new(b"Ed25519/BabyJubJub DLEQ");
        // ChannelWitness guarantees the scalar is valid in both fields, so this should not fail
        let (proof, (xmr_scalar, snark_scalar)) =
            ConciseLinearDLEq::prove_without_bias(rng, &mut transcript, xmr_bjj_generators(), Zeroizing::new(secret))
                .ok_or(DleqError::Ed25519ScalarTooLarge)?;
        // Compute public points from the scalars returned by the proof
        let xmr_point = Ed25519::generator() * *xmr_scalar;
        let snark_point = BabyJubJub::generator() * *snark_scalar;
        Ok((DleqMoneroBjj(proof), ChannelWitnessPublic::new(xmr_point, snark_point)))
    }

    fn verify_dleq(proof: &Self::Proof, public_points: &ChannelWitnessPublic<BabyJubJub>) -> Result<(), DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/BabyJubJub DLEQ");
        let mut rng = OsRng;
        let (x_rec, y_rec) = proof
            .0
            .verify(&mut rng, &mut transcript, xmr_bjj_generators())
            .map_err(|_| DleqError::VerificationFailure)?;
        match public_points.as_xmr_point().eq(&x_rec) && public_points.snark_point().eq(&y_rec) {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError> {
        let proof = DleqMoneroBjj::read(reader)?;
        Ok(proof)
    }
}

#[derive(Clone)]
pub struct DleqMoneroBitcoin(pub ConciseLinearDLEq<<Ed25519 as Ciphersuite>::G, <Secp256k1 as Ciphersuite>::G>);

impl DleqMoneroBitcoin {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let proof = ConciseLinearDLEq::<<Ed25519 as Ciphersuite>::G, <Secp256k1 as Ciphersuite>::G>::read(reader)?;
        Ok(DleqMoneroBitcoin(proof))
    }
}

impl Writable for DleqMoneroBitcoin {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.0.write(writer)
    }
}

#[derive(Clone)]
pub struct DleqMoneroGrumpkin(pub ConciseLinearDLEq<<Ed25519 as Ciphersuite>::G, <Grumpkin as Ciphersuite>::G>);

impl DleqMoneroGrumpkin {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let proof = ConciseLinearDLEq::<<Ed25519 as Ciphersuite>::G, <Grumpkin as Ciphersuite>::G>::read(reader)?;
        Ok(DleqMoneroGrumpkin(proof))
    }
}

impl Writable for DleqMoneroGrumpkin {
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.0.write(writer)
    }
}

impl Dleq<Secp256k1> for Ed25519 {
    type Proof = DleqMoneroBitcoin;

    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &ChannelWitness<Secp256k1>,
    ) -> Result<(Self::Proof, ChannelWitnessPublic<Secp256k1>), DleqError> {
        let secret = *witness.offset();
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Secp256k1 DLEQ");
        let (proof, (xmr_scalar, snark_scalar)) =
            ConciseLinearDLEq::prove_without_bias(rng, &mut transcript, xmr_btc_generators(), Zeroizing::new(secret))
                .ok_or(DleqError::Ed25519ScalarTooLarge)?;
        // Compute public points from the scalars returned by the proof
        let xmr_point = Ed25519::generator() * *xmr_scalar;
        let snark_point = Secp256k1::generator() * *snark_scalar;
        Ok((DleqMoneroBitcoin(proof), ChannelWitnessPublic::new(xmr_point, snark_point)))
    }

    fn verify_dleq(proof: &Self::Proof, public_points: &ChannelWitnessPublic<Secp256k1>) -> Result<(), DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Secp256k1 DLEQ");
        let mut rng = OsRng;
        let (x_rec, y_rec) = proof
            .0
            .verify(&mut rng, &mut transcript, xmr_btc_generators())
            .map_err(|_| DleqError::VerificationFailure)?;
        match public_points.as_xmr_point().eq(&x_rec) && public_points.snark_point().eq(&y_rec) {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError> {
        let proof = DleqMoneroBitcoin::read(reader)?;
        Ok(proof)
    }
}

impl Dleq<Grumpkin> for Ed25519 {
    type Proof = DleqMoneroGrumpkin;

    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
        witness: &ChannelWitness<Grumpkin>,
    ) -> Result<(Self::Proof, ChannelWitnessPublic<Grumpkin>), DleqError> {
        let secret = *witness.offset();
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Grumpkin DLEQ");
        let (proof, (xmr_scalar, snark_scalar)) = ConciseLinearDLEq::prove_without_bias(
            rng,
            &mut transcript,
            xmr_grumpkin_generators(),
            Zeroizing::new(secret),
        )
        .ok_or(DleqError::Ed25519ScalarTooLarge)?;
        // Compute public points from the scalars returned by the proof
        let xmr_point = Ed25519::generator() * *xmr_scalar;
        let snark_point = Grumpkin::generator() * *snark_scalar;
        Ok((DleqMoneroGrumpkin(proof), ChannelWitnessPublic::new(xmr_point, snark_point)))
    }

    fn verify_dleq(proof: &Self::Proof, public_points: &ChannelWitnessPublic<Grumpkin>) -> Result<(), DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Grumpkin DLEQ");
        let mut rng = OsRng;
        let (x_rec, y_rec) = proof
            .0
            .verify(&mut rng, &mut transcript, xmr_grumpkin_generators())
            .map_err(|_| DleqError::VerificationFailure)?;
        match public_points.as_xmr_point().eq(&x_rec) && public_points.snark_point().eq(&y_rec) {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError> {
        let proof = DleqMoneroGrumpkin::read(reader)?;
        Ok(proof)
    }
}

fn xmr_bjj_generators() -> (Generators<XmrPoint>, Generators<BjjPoint>) {
    let monero_gen = monero_generators();
    let bjj_gen = grease_babyjubjub::generators();
    let bjj_gen =
        Generators::new(bjj_gen[0], bjj_gen[1]).expect("Hardcoded generators for BabyJubJub failed to generate");
    (monero_gen, bjj_gen)
}

fn monero_generators() -> Generators<EdwardsPoint> {
    let monero_gen = Generators::new(
        Ed25519::generator(),
        str_to_g("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"),
    )
    .expect("Hardcoded generators for Monero failed to generate");
    monero_gen
}

fn xmr_btc_generators() -> (Generators<XmrPoint>, Generators<ProjectivePoint>) {
    let monero_gen = monero_generators();
    let btc_gen = Generators::new(
        Secp256k1::generator(),
        str_to_g("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"),
    )
    .expect("Hardcoded generators for Bitcoin failed to generate");
    (monero_gen, btc_gen)
}

fn xmr_grumpkin_generators() -> (Generators<XmrPoint>, Generators<GrumpkinPoint>) {
    let monero_gen = monero_generators();
    let grumpkin_gen = grease_grumpkin::generators();
    let grumpkin_gen = Generators::new(grumpkin_gen[0], grumpkin_gen[1])
        .expect("Hardcoded generators for Grumpkin failed to generate");
    (monero_gen, grumpkin_gen)
}

fn str_to_g<G: GroupEncoding>(s: &str) -> G {
    let mut encoding = <G as GroupEncoding>::Repr::default();
    if let Err(e) = hex::decode_to_slice(s, encoding.as_mut()) {
        panic!("Hardcoded generator point is not valid hex: {e}");
    }
    G::from_bytes(&encoding).unwrap()
}

fn ownership_challenge(nonce_pub: &XmrPoint, public_point: &XmrPoint) -> XmrScalar {
    let mut t = RecommendedTranscript::new(b"Witness Ownership");
    t.append_message(b"nonce", nonce_pub.to_bytes());
    t.append_message(b"point", public_point.to_bytes());
    <Ed25519 as Ciphersuite>::hash_to_F(b"message_challenge", &t.challenge(b"challenge"))
}

#[derive(Clone)]
pub struct DleqProof<SF, D>
where
    SF: Curve,
    D: Dleq<SF>,
{
    pub proof: D::Proof,
    pub public_points: ChannelWitnessPublic<SF>,
}

impl<SF, D> std::fmt::Debug for DleqProof<SF, D>
where
    SF: Curve,
    D: Dleq<SF>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DleqProof")
            .field("xmr_point", self.public_points.as_xmr_point())
            .field("foreign_point", self.public_points.snark_point())
            .finish()
    }
}

impl<SF, D> DleqProof<SF, D>
where
    SF: Curve,
    D: Dleq<SF>,
{
    pub fn new(proof: D::Proof, public_points: ChannelWitnessPublic<SF>) -> Self {
        Self { proof, public_points }
    }

    pub fn verify(&self) -> Result<(), DleqError> {
        D::verify_dleq(&self.proof, &self.public_points)
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let proof = D::read(reader).map_err(|e| ReadError::new("DLEQ Proof", format!("Failed to read proof: {e}")))?;
        let public_points = ChannelWitnessPublic::read(reader)?;
        Ok(DleqProof { proof, public_points })
    }
}

impl<SF, D> Writable for DleqProof<SF, D>
where
    SF: Curve,
    D: Dleq<SF>,
{
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.proof.write(writer)?;
        self.public_points.write(writer)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DleqError {
    #[error("The provided scalar cannot be represented as a scalar on the Ed25519 curve.")]
    InvalidEd25519Scalar,
    #[error("The provided scalar cannot be represented as a field element on the Foreign curve.")]
    InvalidForeignFieldElement,
    #[error("The ED25519 scalar cannot be represented on the Foreign curve.")]
    Ed25519ScalarTooLarge,
    #[error("An equivalent Foreign and Ed25519 representation could not be found during initial witness generation.")]
    InitializationFailure,
    #[error("DLEQ proof verification failed.")]
    VerificationFailure,
    #[error("I/O error occurred during reading data.")]
    ReadError(#[from] std::io::Error),
}

#[cfg(test)]
mod test {
    use crate::cryptography::dleq::{Dleq, DleqError};
    use crate::cryptography::witness::ChannelWitnessPublic;
    use crate::cryptography::{AsXmrPoint, ChannelWitness};
    use ciphersuite::group::GroupEncoding;
    use ciphersuite::{Ciphersuite, Ed25519, Secp256k1};
    use grease_babyjubjub::BabyJubJub;
    use grease_grumpkin::Grumpkin;
    use modular_frost::sign::Writable;
    use rand_core::OsRng;
    use std::ops::Add;

    #[test]
    fn test_equivalence_ed25519_ed25519() {
        let mut rng = OsRng;
        let witness = ChannelWitness::<Ed25519>::random();
        let (proof, public_points) = <Ed25519 as Dleq<Ed25519>>::generate_dleq(&mut rng, &witness).unwrap();
        let x_point = *public_points.as_xmr_point();
        let y_point = *public_points.snark_point();
        println!("x: {}, y: {}", hex::encode(x_point.to_bytes()), hex::encode(y_point.to_bytes()));
        assert_eq!(x_point, y_point);
        assert!(
            <Ed25519 as Dleq<Ed25519>>::verify_dleq(&proof, &public_points).is_ok(),
            "DLEQ Proof did not verify"
        );
        assert_eq!(
            proof.serialize().len(),
            64,
            "Proof is not 64 bytes, but {}",
            proof.serialize().len()
        );
        let bad_points = ChannelWitnessPublic::new(x_point, x_point.add(&x_point));
        assert!(matches!(
            <Ed25519 as Dleq<Ed25519>>::verify_dleq(&proof, &bad_points),
            Err(DleqError::VerificationFailure)
        ));
    }

    #[test]
    fn test_equivalence_ed25519_secp256k() {
        let mut rng = OsRng;
        let witness = ChannelWitness::<Secp256k1>::random();
        let (proof, public_points) = <Ed25519 as Dleq<Secp256k1>>::generate_dleq(&mut rng, &witness).unwrap();
        let x_point = *public_points.as_xmr_point();
        let y_point = *public_points.snark_point();
        let mut v = Vec::<u8>::with_capacity(64 * 1024);
        proof.write(&mut v).expect("Writing proof to vec cannot fail");
        assert_eq!(v.len(), 44607);
        println!(
            "proof: {} bytes xmr: {}, btc: {}",
            v.len(),
            hex::encode(x_point.to_bytes()),
            hex::encode(y_point.to_bytes())
        );
        assert!(
            <Ed25519 as Dleq<Secp256k1>>::verify_dleq(&proof, &public_points).is_ok(),
            "XMR<>BTC DLEQ Proof did not verify"
        );
        let bad_points = ChannelWitnessPublic::new(x_point.add(&x_point), y_point);
        assert!(matches!(
            <Ed25519 as Dleq<Secp256k1>>::verify_dleq(&proof, &bad_points),
            Err(DleqError::VerificationFailure)
        ));
    }

    #[test]
    fn test_equivalence_ed25519_babyjubjub() {
        let mut rng = OsRng;
        // ChannelWitness guarantees the scalar is valid in both Ed25519 and BabyJubJub fields
        let witness = ChannelWitness::<BabyJubJub>::random();
        let (proof, public_points) = <Ed25519 as Dleq<BabyJubJub>>::generate_dleq(&mut rng, &witness)
            .expect("ChannelWitness guarantees valid scalar in both fields");
        let x_point = *public_points.as_xmr_point();
        let y_point = *public_points.snark_point();
        let mut v = Vec::<u8>::with_capacity(64 * 1024);
        proof.write(&mut v).expect("Writing proof to vec cannot fail");
        assert_eq!(v.len(), 44128);
        println!(
            "proof: {} bytes xmr: {}, bjj: {}",
            v.len(),
            hex::encode(x_point.to_bytes()),
            hex::encode(y_point.to_bytes())
        );
        assert!(
            <Ed25519 as Dleq<BabyJubJub>>::verify_dleq(&proof, &public_points).is_ok(),
            "XMR<>BJJ DLEQ Proof did not verify"
        );
        let bad_points = ChannelWitnessPublic::new(x_point.add(&x_point), y_point);
        assert!(matches!(
            <Ed25519 as Dleq<BabyJubJub>>::verify_dleq(&proof, &bad_points),
            Err(DleqError::VerificationFailure)
        ));
    }

    #[test]
    fn test_equivalence_ed25519_grumpkin() {
        let mut rng = OsRng;
        let witness = ChannelWitness::<Grumpkin>::random();
        let (proof, public_points) = <Ed25519 as Dleq<Grumpkin>>::generate_dleq(&mut rng, &witness).unwrap();
        let x_point = *public_points.as_xmr_point();
        let y_point = *public_points.snark_point();
        let mut v = Vec::<u8>::with_capacity(64 * 1024);
        proof.write(&mut v).expect("Writing proof to vec cannot fail");
        assert_eq!(v.len(), 44480);
        println!(
            "proof: {} bytes xmr: {}, grumpkin: {}",
            v.len(),
            hex::encode(x_point.to_bytes()),
            hex::encode(y_point.to_bytes())
        );
        assert!(
            <Ed25519 as Dleq<Grumpkin>>::verify_dleq(&proof, &public_points).is_ok(),
            "XMR<>Grumpkin DLEQ Proof did not verify"
        );
        // Roundtrip: deserialize and re-verify
        let proof_roundtrip =
            <Ed25519 as Dleq<Grumpkin>>::read(&mut v.as_slice()).expect("Failed to read proof from serialized bytes");
        assert!(
            <Ed25519 as Dleq<Grumpkin>>::verify_dleq(&proof_roundtrip, &public_points).is_ok(),
            "XMR<>Grumpkin DLEQ Proof roundtrip did not verify"
        );
        let bad_points = ChannelWitnessPublic::new(x_point.add(&x_point), y_point);
        assert!(matches!(
            <Ed25519 as Dleq<Grumpkin>>::verify_dleq(&proof, &bad_points),
            Err(DleqError::VerificationFailure)
        ));
    }
}
