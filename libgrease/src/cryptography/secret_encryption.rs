use crate::cryptography::ecdh_encrypt::EncryptedScalar;
use crate::error::ReadError;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::Ciphersuite;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::io::Read;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An encrypted secret $\Xi$ for a participant in the payment channel.
///
/// `channel_role` indicates the role of the party who created the shard.
/// Wraps [`EncryptedScalar`] with additional role metadata.
#[derive(Clone)]
pub struct EncryptedSecret<C: Ciphersuite> {
    /// The underlying ECDH-encrypted scalar.
    inner: EncryptedScalar<C>,
    /// The role of the party who created this secret.
    role: ChannelRole,
}

impl<C: Ciphersuite> HasRole for EncryptedSecret<C> {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

/// Combines a domain separator with the channel role byte.
fn role_bound_domain<B: AsRef<[u8]>>(domain: B, role: ChannelRole) -> Vec<u8> {
    [domain.as_ref(), &[role.as_u8()]].concat()
}

impl<C: Ciphersuite> EncryptedSecret<C> {
    /// Encrypt a witness shard for `recipient` using ephemeral Diffie-Hellman key exchange.
    pub fn encrypt<R, B>(mut secret: SecretWithRole<C>, recipient: &C::G, rng: &mut R, domain: B) -> Self
    where
        R: RngCore + CryptoRng,
        B: AsRef<[u8]>,
    {
        let role = secret.role;
        let inner = EncryptedScalar::encrypt(&secret.secret, recipient, rng, role_bound_domain(domain, role));
        secret.zeroize();
        Self { inner, role }
    }

    /// Read an EncryptedSecret from something implementing Read.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let role = reader
            .read_u8()
            .map_err(|e| ReadError::new("EncryptedSecret.role", e.to_string()))
            .and_then(ChannelRole::try_from)?;
        let inner = EncryptedScalar::read(reader)?;
        Ok(Self { inner, role })
    }

    /// Decrypt a secret using the recipient's secret key on the given curve using ephemeral Diffie-Hellman exchange.
    pub fn decrypt<B: AsRef<[u8]>>(&self, secret: &C::F, domain: B) -> SecretWithRole<C> {
        let decrypted = self.inner.decrypt(secret, role_bound_domain(domain, self.role));
        SecretWithRole { secret: decrypted, role: self.role }
    }
}

/// A convenience struct that wraps a secret along with the channel role of the party it belongs to. This is used
/// especially in the context of encrypted secrets for the KES in the payment channel. Storing the role alongside the
/// secret helps prevent bugs where secrets might be mixed up between parties.
#[derive(Clone)]
pub struct SecretWithRole<C: Ciphersuite> {
    secret: C::F,
    role: ChannelRole,
}

impl<C: Ciphersuite> Debug for SecretWithRole<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shard").field("shard", &"[REDACTED]").field("role", &self.role).finish()
    }
}

impl<C: Ciphersuite> SecretWithRole<C> {
    pub fn new(secret: C::F, role: ChannelRole) -> Self {
        Self { secret, role }
    }

    pub fn secret(&self) -> &C::F {
        &self.secret
    }
}

impl<C: Ciphersuite> ConstantTimeEq for SecretWithRole<C> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secret.ct_eq(&other.secret) & subtle::Choice::from((self.role == other.role) as u8)
    }
}

impl<C: Ciphersuite> Zeroize for SecretWithRole<C> {
    fn zeroize(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: Ciphersuite> ZeroizeOnDrop for SecretWithRole<C> {}

impl<C: Ciphersuite> Drop for SecretWithRole<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: Ciphersuite> HasRole for SecretWithRole<C> {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<C: Ciphersuite> Writable for EncryptedSecret<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.emit_u8(self.role.as_u8())?;
        self.inner.write(writer)
    }
}

#[cfg(test)]
mod tests {
    use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
    use crate::payment_channel::ChannelRole;
    use ciphersuite::Ciphersuite;
    use ciphersuite::Ed25519;
    use dalek_ff_group::{EdwardsPoint, Scalar as EdScalar};
    use grease_babyjubjub::{BabyJubJub, Scalar as BjjScalar};
    use modular_frost::curve::Field;
    use modular_frost::curve::Group;
    use subtle::ConstantTimeEq;

    #[test]
    fn encrypt_decrypt_ed25519() {
        let mut rng = rand_core::OsRng;
        let recipient_secret = EdScalar::random(&mut rng);
        let recipient_public = EdwardsPoint::generator() * &recipient_secret;
        let shard = SecretWithRole::new(EdScalar::random(rng), ChannelRole::Customer);
        let encrypted = EncryptedSecret::<Ed25519>::encrypt(shard.clone(), &recipient_public, &mut rng, "test");
        let decrypted_shard = encrypted.decrypt(&recipient_secret, "test");
        assert_eq!(shard.ct_eq(&decrypted_shard).unwrap_u8(), 1);
        let decrypted_shard = encrypted.decrypt(&recipient_secret, "wrong");
        assert_eq!(shard.ct_eq(&decrypted_shard).unwrap_u8(), 0);
    }

    #[test]
    fn encrypt_decrypt_babyjubjub() {
        let mut rng = rand_core::OsRng;
        let shard = SecretWithRole::new(BjjScalar::random(rng), ChannelRole::Customer);
        let recipient_secret = BjjScalar::random(&mut rng);
        let recipient_public = BabyJubJub::generator() * &recipient_secret;
        let encrypted = EncryptedSecret::<BabyJubJub>::encrypt(shard.clone(), &recipient_public, &mut rng, "test");
        let decrypted_shard = encrypted.decrypt(&recipient_secret, "test");
        assert_eq!(shard.ct_eq(&decrypted_shard).unwrap_u8(), 1);
    }
}
