use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::grease_protocol::adapter_signature::AdapterSignatureHandler;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::XmrScalar;
use ciphersuite::Ed25519;
use modular_frost::curve::Curve as FrostCurve;
use rand_core::{CryptoRng, RngCore};
use std::ops::Deref;
use thiserror::Error;
use zeroize::Zeroizing;

pub trait KesClient<SF: FrostCurve>: AdapterSignatureHandler + Sized + HasRole
where
    Ed25519: Dleq<SF>,
{
    /// TODO: delgate DLEQ proof generation to VCOF implementation, since it's possible that we could replace it with something else.
    /// Generate a new KES client instance with fresh secrets and an associated DLEQ proof.
    ///
    /// This method generates a new set of secrets and proofs for the KES that knows the discrete log of the given
    /// point (`public_key`) on curve `SF`. The role indicates whether this client is for a merchant or customer.
    ///
    /// After a successful call to this function, the DLEQ proof, the equivalent points on both curves, and the
    /// respective secrets (discrete logs) will be available via the getter methods.
    fn generate<R: RngCore + CryptoRng>(
        _rng: &mut R,
        _kes_pubkey: SF::G,
        _role: ChannelRole,
    ) -> Result<Self, KesClientError> {
        todo!("Delegate DLEQ proof generation to VCOF implementation");
    }

    /// Implementations must implement this constructor, but don't call it directly. Use `generate` instead.
    fn new(
        kes_pubkey: SF::G,
        proof: DleqProof<SF, Ed25519>,
        secret: Zeroizing<XmrScalar>,
        secret_fk: Zeroizing<SF::F>,
        channel_role: ChannelRole,
    ) -> Self;

    fn kes_public_key(&self) -> SF::G;
    fn dleq_proof(&self) -> &DleqProof<SF, Ed25519>;
    fn secret_for_kes(&self) -> &Zeroizing<SF::F>;
    fn secret(&self) -> &Zeroizing<XmrScalar>;

    fn domain_separation_tag() -> &'static [u8] {
        b"GreaseEncryptToKES"
    }

    /// Encrypt the secret to the KES using ECDH (Elliptic-curve Diffie–Hellman) key agreement protocol.
    ///
    /// The encryption process includes a domain separation step using [`domain_separation_tag`], which SHOULD be
    /// overridden in the trait implementation.
    fn encrypt_to_kes<R: RngCore + CryptoRng>(&self, rng: &mut R) -> EncryptedSecret<SF> {
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
}

pub struct KesSecrets<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    kes_pubkey: SF::G,
    dleq_proof: DleqProof<SF, Ed25519>,
    adapter_sig_offset: Zeroizing<XmrScalar>,
    offset_kes: Zeroizing<SF::F>,
    role: ChannelRole,
}

impl<SF> std::fmt::Debug for KesSecrets<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KesSecrets")
            .field("role", &self.role)
            .field("kes_pubkey", &"<hidden>")
            .field("adapter_sig_offset", &"<secret>")
            .finish()
    }
}

impl<SF> HasRole for KesSecrets<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<SF> AdapterSignatureHandler for KesSecrets<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn initialize_signature_offset(&mut self) {
        // No-op: the offset is generated during creation and should not be changed.
    }

    /// The KES secrets only hold ω0 and cannot support updates.
    fn update_signature_offset(&mut self, _: &XmrScalar) {
        panic!("KES client signature offset cannot be updated after initialization.");
    }

    fn adapter_signature_offset(&self) -> &XmrScalar {
        &self.adapter_sig_offset
    }
}

impl<SF> KesClient<SF> for KesSecrets<SF>
where
    SF: FrostCurve,
    Ed25519: Dleq<SF>,
{
    fn new(
        kes_pubkey: SF::G,
        proof: DleqProof<SF, Ed25519>,
        secret: Zeroizing<XmrScalar>,
        secret_fk: Zeroizing<SF::F>,
        channel_role: ChannelRole,
    ) -> Self {
        Self { kes_pubkey, dleq_proof: proof, adapter_sig_offset: secret, offset_kes: secret_fk, role: channel_role }
    }

    fn kes_public_key(&self) -> SF::G {
        self.kes_pubkey
    }

    fn dleq_proof(&self) -> &DleqProof<SF, Ed25519> {
        &self.dleq_proof
    }

    fn secret_for_kes(&self) -> &Zeroizing<SF::F> {
        &self.offset_kes
    }

    fn secret(&self) -> &Zeroizing<XmrScalar> {
        &self.adapter_sig_offset
    }
}
