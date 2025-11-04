use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::grease_protocol::adapter_signature::AdapterSignatureHandler;
use crate::grease_protocol::error::DleqError;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use ciphersuite::{Ciphersuite, Ed25519};
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use std::ops::Deref;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait KesClient<C: FrostCurve>: AdapterSignatureHandler + Sized + HasRole
where
    Ed25519: Dleq<C>,
{
    /// Generate a new KES client instance with fresh secrets and an associated DLEQ proof.
    ///
    /// This method generates a new set of secrets and proofs for the KES that knows the discrete log of the given
    /// point (`public_key`) on curve `C`. The role indicates whether this client is for a merchant or customer.
    ///
    /// After a successful call to this function, the DLEQ proof, the equivalent points on both curves, and the
    /// respective secrets (discrete logs) will be available via the getter methods.
    fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        kes_pubkey: C::G,
        role: ChannelRole,
    ) -> Result<Self, KesClientError> {
        let (proof, (adapter_sig_offset, offset_kes)) =
            <Ed25519 as Dleq<C>>::generate_dleq(rng).map_err(KesClientError::DleqProofGenerationError)?;
        let q_ed25519 = Ed25519::generator() * adapter_sig_offset;
        let q_kes = C::generator() * offset_kes;
        let dleq_proof = DleqProof::new(proof, q_ed25519, q_kes);
        let result = Self::new(
            kes_pubkey,
            dleq_proof,
            Zeroizing::new(adapter_sig_offset),
            Zeroizing::new(offset_kes),
            role,
        );
        Ok(result)
    }

    /// Implementations must implement this constructor, but don't call it directly. Use `generate` instead.
    fn new(
        kes_pubkey: C::G,
        proof: DleqProof<C, Ed25519>,
        secret: Zeroizing<XmrScalar>,
        secret_fk: Zeroizing<C::F>,
        channel_role: ChannelRole,
    ) -> Self;

    fn kes_public_key(&self) -> C::G;
    fn dleq_proof(&self) -> &DleqProof<C, Ed25519>;
    fn secret_for_kes(&self) -> &Zeroizing<C::F>;
    fn secret(&self) -> &Zeroizing<XmrScalar>;

    fn domain_separation_tag() -> &'static [u8] {
        b"GreaseEncryptToKES"
    }

    /// Encrypt the secret to the KES using ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol.
    ///
    /// The encryption process includes a domain separation step using [`domain_separation_tag`], which SHOULD be
    /// overridden in the trait implementation.
    fn encrypt_to_kes<R: RngCore + CryptoRng>(&self, rng: &mut R) -> EncryptedSecret<C> {
        let role = self.role();
        let kes_secret = self.secret_for_kes();
        let secret = SecretWithRole::new(*kes_secret.deref(), role);
        EncryptedSecret::encrypt(secret, &self.kes_public_key(), rng, Self::domain_separation_tag())
    }
}

#[derive(Debug, Error)]
pub enum KesClientError {
    #[error("The provided KES public key is invalid for the given curve.")]
    InvalidKesPublicKey,
    #[error("DLEQ proof generation failed: {0}")]
    DleqProofGenerationError(DleqError),
}

pub struct KesSecrets<C>
where
    C: FrostCurve,
    Ed25519: Dleq<C>,
{
    kes_pubkey: C::G,
    dleq_proof: DleqProof<C, Ed25519>,
    adapter_sig_offset: Zeroizing<XmrScalar>,
    offset_kes: Zeroizing<C::F>,
    role: ChannelRole,
}

impl<C> HasRole for KesSecrets<C>
where
    C: FrostCurve,
    Ed25519: Dleq<C>,
{
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<C> AdapterSignatureHandler for KesSecrets<C>
where
    C: FrostCurve,
    Ed25519: Dleq<C>,
{
    fn initialize_signature_offset(&mut self) {
        // No-op: the offset is generated during creation and should not be changed.
    }

    /// The KES secrets only hold ω0 and cannot support updates.
    fn update_signature_offset(&mut self, _: XmrScalar) {
        panic!("KES client signature offset cannot be updated after initialization.");
    }

    fn adapter_signature_offset(&self) -> &XmrScalar {
        &self.adapter_sig_offset
    }
}

impl<C> KesClient<C> for KesSecrets<C>
where
    C: FrostCurve,
    Ed25519: Dleq<C>,
{
    fn new(
        kes_pubkey: C::G,
        proof: DleqProof<C, Ed25519>,
        secret: Zeroizing<XmrScalar>,
        secret_fk: Zeroizing<C::F>,
        channel_role: ChannelRole,
    ) -> Self {
        Self { kes_pubkey, dleq_proof: proof, adapter_sig_offset: secret, offset_kes: secret_fk, role: channel_role }
    }

    fn kes_public_key(&self) -> C::G {
        self.kes_pubkey
    }

    fn dleq_proof(&self) -> &DleqProof<C, Ed25519> {
        &self.dleq_proof
    }

    fn secret_for_kes(&self) -> &Zeroizing<C::F> {
        &self.offset_kes
    }

    fn secret(&self) -> &Zeroizing<XmrScalar> {
        &self.adapter_sig_offset
    }
}
