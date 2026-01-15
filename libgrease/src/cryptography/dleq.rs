use crate::error::ReadError;
use crate::grease_protocol::error::DleqError;
use crate::grease_protocol::utils::write_group_element;
use blake2::Blake2b512;
use ciphersuite::group::ff::Field;
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519, Secp256k1};
use dalek_ff_group::{EdwardsPoint as XmrPoint, Scalar as XmrScalar};
use digest::{Digest, Update};
use dleq::cross_group::{ConciseLinearDLEq, Generators};
use flexible_transcript::{RecommendedTranscript, Transcript};
use grease_babyjubjub::{BabyJubJub, BjjPoint};
use k256::ProjectivePoint;
use modular_frost::algorithm::SchnorrSignature;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::io;
use std::io::{Read, Write};
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

pub type DleqResult<C> = (<Ed25519 as Dleq<C>>::Proof, (XmrScalar, <C as Ciphersuite>::F));
pub trait Dleq<C: Curve>: Curve {
    type Proof: Clone + Writable;

    /// Generate a new set of scalars (x, y) such that they are equivalent on both curves, in a sense that they stem
    /// from the same binary representation. Returns the proof and the scalars (x, y).
    fn generate_dleq<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::Proof, (XmrScalar, <C as Ciphersuite>::F)), DleqError>;

    /// Verify that the provided proof shows that the discrete log of p1 on Ed25519 is the same as the discrete log
    /// of p2 on curve C, AND that the prover possesses knowledge of both discrete logs.
    fn verify_dleq(proof: &Self::Proof, p1: &XmrPoint, p2: &<C as Ciphersuite>::G) -> Result<(), DleqError>;

    /// Read the proof from a reader
    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError>;
}

impl Dleq<Ed25519> for Ed25519 {
    type Proof = EdSchnorrSignature;

    fn generate_dleq<R: RngCore + CryptoRng>(rng: &mut R) -> Result<DleqResult<Ed25519>, DleqError> {
        let secret = XmrScalar::random(&mut *rng);
        let nonce = <Ed25519 as Ciphersuite>::random_nonzero_F(&mut *rng);
        let nonce_pub = Ed25519::generator() * nonce;
        let public_point = Ed25519::generator() * secret;
        let challenge = ownership_challenge(&nonce_pub, &public_point);
        // C::F is already Zeroize. Maybe this gets cleaned up upstream at some point
        let mut zs = Zeroizing::new(secret);
        let proof = SchnorrSignature::sign(&zs, Zeroizing::new(nonce), challenge);
        zs.zeroize();
        Ok((EdSchnorrSignature(proof), (secret, secret)))
    }

    fn verify_dleq(proof: &Self::Proof, x: &XmrPoint, y: &XmrPoint) -> Result<(), DleqError> {
        let valid = x.eq(y) && {
            let challenge = ownership_challenge(&proof.0.R, x);
            proof.0.verify(*x, challenge)
        };
        match valid {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self::Proof, DleqError> {
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

    fn generate_dleq<R: RngCore + CryptoRng>(rng: &mut R) -> Result<DleqResult<BabyJubJub>, DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/BabyJubJub DLEQ");
        let mut nonce = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(nonce.as_mut_slice());
        let digest = Blake2b512::new().chain(&nonce);
        nonce.zeroize();
        let (proof, (xmr, fk)) = ConciseLinearDLEq::prove(rng, &mut transcript, xmr_bjj_generators(), digest);
        // Unwraps one layer of Zeroizing:
        let xmr = *xmr;
        let foreign_key = <BabyJubJub as Ciphersuite>::F::from(fk.0);
        Ok((DleqMoneroBjj(proof), (xmr, foreign_key)))
    }

    fn verify_dleq(proof: &Self::Proof, p1: &XmrPoint, p2: &<BabyJubJub as Ciphersuite>::G) -> Result<(), DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/BabyJubJub DLEQ");
        let mut rng = OsRng;
        let (x_rec, y_rec) = proof
            .0
            .verify(&mut rng, &mut transcript, xmr_bjj_generators())
            .map_err(|_| DleqError::VerificationFailure)?;
        match p1.eq(&x_rec) && p2.eq(&y_rec) {
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

impl Dleq<Secp256k1> for Ed25519 {
    type Proof = DleqMoneroBitcoin;

    fn generate_dleq<R: RngCore + CryptoRng>(rng: &mut R) -> Result<DleqResult<Secp256k1>, DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Secp256k1 DLEQ");
        let mut nonce = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(nonce.as_mut_slice());
        let digest = Blake2b512::new().chain(&nonce);
        nonce.zeroize();
        let (proof, (xmr, fk)) = ConciseLinearDLEq::prove(rng, &mut transcript, xmr_btc_generators(), digest);
        Ok((DleqMoneroBitcoin(proof), (*xmr, *fk)))
    }

    fn verify_dleq(proof: &Self::Proof, x: &XmrPoint, y: &<Secp256k1 as Ciphersuite>::G) -> Result<(), DleqError> {
        let mut transcript = RecommendedTranscript::new(b"Ed25519/Secp256k1 DLEQ");
        let mut rng = OsRng;
        let (x_rec, y_rec) = proof
            .0
            .verify(&mut rng, &mut transcript, xmr_btc_generators())
            .map_err(|_| DleqError::VerificationFailure)?;
        match x.eq(&x_rec) && y.eq(&y_rec) {
            true => Ok(()),
            false => Err(DleqError::VerificationFailure),
        }
    }

    fn read<R: Read>(reader: &mut R) -> Result<Self::Proof, DleqError> {
        let proof = DleqMoneroBitcoin::read(reader)?;
        Ok(proof)
    }
}

fn xmr_bjj_generators() -> (Generators<XmrPoint>, Generators<BjjPoint>) {
    let monero_gen = Generators::new(
        Ed25519::generator(),
        str_to_g("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"),
    )
    .expect("Hardcoded generators for Monero failed to generate");
    let bjj_gen = grease_babyjubjub::generators();
    let bjj_gen =
        Generators::new(bjj_gen[0], bjj_gen[1]).expect("Hardcoded generators for BabyJubJub failed to generate");
    (monero_gen, bjj_gen)
}

fn xmr_btc_generators() -> (Generators<XmrPoint>, Generators<ProjectivePoint>) {
    let monero_gen = Generators::new(
        Ed25519::generator(),
        str_to_g("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"),
    )
    .expect("Hardcoded generators for Monero failed to generate");
    let btc_gen = Generators::new(
        Secp256k1::generator(),
        str_to_g("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"),
    )
    .expect("Hardcoded generators for Bitcoin failed to generate");
    (monero_gen, btc_gen)
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
pub struct DleqProof<C, D>
where
    C: Curve,
    D: Dleq<C>,
{
    pub proof: D::Proof,
    pub xmr_point: XmrPoint,
    pub foreign_point: <C as Ciphersuite>::G,
}

impl<C, D> std::fmt::Debug for DleqProof<C, D>
where
    C: Curve,
    D: Dleq<C>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DleqProof")
            .field("xmr_point", &self.xmr_point)
            .field("foreign_point", &"<curve point>")
            .finish()
    }
}

impl<C, D> DleqProof<C, D>
where
    C: Curve,
    D: Dleq<C>,
{
    pub fn new(proof: D::Proof, xmr_point: XmrPoint, foreign_point: <C as Ciphersuite>::G) -> Self {
        Self { proof, xmr_point, foreign_point }
    }

    pub fn verify(&self) -> Result<(), DleqError> {
        D::verify_dleq(&self.proof, &self.xmr_point, &self.foreign_point)
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let proof =
            D::read(reader).map_err(|e| ReadError::new("DLEQ Proof", format!("Failed to read proof: {}", e)))?;
        let xmr_point = crate::grease_protocol::utils::read_group_element::<Ed25519, R>(reader)
            .map_err(|e| ReadError::new("DLEQ Proof", format!("Failed to read XMR point: {}", e)))?;
        let foreign_point = crate::grease_protocol::utils::read_group_element::<C, R>(reader)
            .map_err(|e| ReadError::new("DLEQ Proof", format!("Failed to read foreign point: {}", e)))?;
        Ok(DleqProof { proof, xmr_point, foreign_point })
    }
}

impl<C, D> Writable for DleqProof<C, D>
where
    C: Curve,
    D: Dleq<C>,
{
    fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.proof.write(writer)?;
        write_group_element::<Ed25519, W>(writer, &self.xmr_point)?;
        write_group_element::<C, W>(writer, &self.foreign_point)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::cryptography::dleq::Dleq;
    use crate::grease_protocol::error::DleqError;
    use ciphersuite::group::ff::PrimeFieldBits;
    use ciphersuite::group::GroupEncoding;
    use ciphersuite::{Ciphersuite, Ed25519, Secp256k1};
    use grease_babyjubjub::BabyJubJub;
    use modular_frost::sign::Writable;
    use rand_core::OsRng;
    use std::ops::Add;

    #[test]
    fn test_equivalence_ed25519_ed25519() {
        let mut rng = OsRng;
        let (proof, (x, y)) = <Ed25519 as Dleq<Ed25519>>::generate_dleq(&mut rng).unwrap();
        let x_point = Ed25519::generator() * x;
        let y_point = Ed25519::generator() * y;
        println!("x: {}, y: {}", hex::encode(x_point.to_bytes()), hex::encode(y_point.to_bytes()));
        assert_eq!(x_point, y_point);
        assert!(
            <Ed25519 as Dleq<Ed25519>>::verify_dleq(&proof, &x_point, &y_point).is_ok(),
            "DLEQ Proof did not verify"
        );
        assert_eq!(
            proof.serialize().len(),
            64,
            "Proof is not 64 bytes, but {}",
            proof.serialize().len()
        );
        let y_point = x_point.add(&x_point);
        assert!(matches!(
            <Ed25519 as Dleq<Ed25519>>::verify_dleq(&proof, &x_point, &y_point),
            Err(DleqError::VerificationFailure)
        ));
        assert_eq!(x.to_bytes(), y.to_bytes());
    }

    #[test]
    fn test_equivalence_ed25519_secp256k() {
        let mut rng = OsRng;
        let (proof, (x, y)) = <Ed25519 as Dleq<Secp256k1>>::generate_dleq(&mut rng).unwrap();
        let x_point = Ed25519::generator() * x;
        let y_point = Secp256k1::generator() * y;
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
            <Ed25519 as Dleq<Secp256k1>>::verify_dleq(&proof, &x_point, &y_point).is_ok(),
            "XMR<>BTC DLEQ Proof did not verify"
        );
        let x_point = x_point.add(&x_point);
        assert!(matches!(
            <Ed25519 as Dleq<Secp256k1>>::verify_dleq(&proof, &x_point, &y_point),
            Err(DleqError::VerificationFailure)
        ));
        assert_eq!(x.to_le_bits(), y.to_le_bits());
    }

    #[test]
    fn test_equivalence_ed25519_babyjubjub() {
        let mut rng = OsRng;
        let (proof, (x, y)) = <Ed25519 as Dleq<BabyJubJub>>::generate_dleq(&mut rng).unwrap();
        let x_point = Ed25519::generator() * x;
        let y_point = BabyJubJub::generator() * y;
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
            <Ed25519 as Dleq<BabyJubJub>>::verify_dleq(&proof, &x_point, &y_point).is_ok(),
            "XMR<>BTC DLEQ Proof did not verify"
        );
        let x_point = x_point.add(&x_point);
        assert!(matches!(
            <Ed25519 as Dleq<BabyJubJub>>::verify_dleq(&proof, &x_point, &y_point),
            Err(DleqError::VerificationFailure)
        ));
        assert_eq!(x.to_le_bits(), y.to_le_bits());
    }
}
