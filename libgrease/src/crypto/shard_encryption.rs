use crate::error::ReadError;
use crate::grease_protocol::utils::{read_field_element, read_group_element, write_field_element, write_group_element};
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use modular_frost::curve::Curve;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::io::Read;
use std::ops::Mul;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DOMAIN: &[u8] = b"FVSS-EncryptedShare";

/// An encrypted witness shard $\X_i$ for a participant in the payment channel.
///
/// Each party encrypts two shards. One for the counterparty, and one for the KES.
/// If `is_kes_shard` is true, this shard is intended for the KES; and `channel_role` indicates the role of the party
/// who created the shard.
/// If `is_kes_shard` is false, this shard is intended for the counterparty; and `channel_role` indicates the role of
/// the recipient.
#[derive(Clone)]
pub struct EncryptedShard<C: Curve> {
    /// The encrypted value of the shard.
    encrypted_shard: C::F,
    /// The public nonce used in the encryption.
    public_nonce: C::G,
    /// The role of the party who created this shard.
    role: ChannelRole,
    /// Whether this shard is intended for the KES.
    is_kes_shard: bool,
}

impl<C: Curve> HasRole for EncryptedShard<C> {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<C: Curve> EncryptedShard<C> {
    /// Encrypt a witness shard for `recipient` using ephemeral Diffie-Hellman key exchange.
    pub fn encrypt_shard<R: RngCore + CryptoRng>(shard: &Shard<C>, recipient: &C::G, rng: &mut R) -> Self {
        let mut nonce = C::random_nonzero_F(rng);
        let public_nonce = C::generator() * &nonce;
        let shared_point = recipient.mul(&nonce);
        let shared_secret = <C as Ciphersuite>::hash_to_F(DOMAIN, shared_point.to_bytes().as_ref());
        let encrypted_point = shared_secret + shard.shard();
        nonce.zeroize();
        Self { role: shard.role(), is_kes_shard: shard.is_kes_shard(), encrypted_shard: encrypted_point, public_nonce }
    }

    /// Read an EncryptedShard from something implementing Read.
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, ReadError> {
        let role = reader
            .read_u8()
            .map_err(|e| ReadError::new("EncryptedShard.role", e.to_string()))
            .and_then(ChannelRole::try_from)?;
        let is_kes_shard =
            reader.read_bool().map_err(|e| ReadError::new("EncryptedShard.is_kes_shard", e.to_string()))?;
        let encrypted_shard =
            read_field_element::<C, _>(reader).map_err(|e| ReadError::new("EncryptedShard.shard", e.to_string()))?;
        let public_nonce = read_group_element::<C, _>(reader)
            .map_err(|e| ReadError::new("EncryptedShard.public_nonce", e.to_string()))?;
        if public_nonce.is_identity().into() {
            return Err(ReadError::new(
                "EncryptedShard.public_nonce",
                "public nonce cannot be the identity element".to_string(),
            ));
        }
        Ok(Self { encrypted_shard, is_kes_shard, role, public_nonce })
    }

    /// Decrypt a witness shard using the recipient's secret key on the given curve using ephemeral Diffie-Hellman exchange.
    pub fn decrypt_shard(&self, secret: &C::F) -> Shard<C> {
        let shared_point = self.public_nonce * secret;
        let shared_secret = <C as Ciphersuite>::hash_to_F(DOMAIN, shared_point.to_bytes().as_ref());
        let shard = self.encrypted_shard - shared_secret;
        Shard { shard, is_kes_shard: self.is_kes_shard, role: self.role }
    }

    /// Get whether this shard is intended for the KES.
    pub fn is_kes_shard(&self) -> bool {
        self.is_kes_shard
    }
}

#[derive(Clone)]
pub struct Shard<C: Curve> {
    shard: C::F,
    is_kes_shard: bool,
    role: ChannelRole,
}

impl<C: Curve> Debug for Shard<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shard")
            .field("shard", &"[REDACTED]")
            .field("is_kes_shard", &self.is_kes_shard)
            .field("role", &self.role)
            .finish()
    }
}

impl<C: Curve> Shard<C> {
    pub fn new(shard: C::F, is_kes_shard: bool, role: ChannelRole) -> Self {
        Self { shard, is_kes_shard, role }
    }

    pub fn shard(&self) -> &C::F {
        &self.shard
    }

    pub fn is_kes_shard(&self) -> bool {
        self.is_kes_shard
    }
}

impl<C: Curve> ConstantTimeEq for Shard<C> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.shard.ct_eq(&other.shard)
            & subtle::Choice::from((self.is_kes_shard == other.is_kes_shard) as u8)
            & subtle::Choice::from((self.role == other.role) as u8)
    }
}

impl<C: Curve> Zeroize for Shard<C> {
    fn zeroize(&mut self) {
        self.shard.zeroize();
    }
}

impl<C: Curve> ZeroizeOnDrop for Shard<C> {}

impl<C: Curve> Drop for Shard<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: Curve> HasRole for Shard<C> {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<C: Curve> Writable for EncryptedShard<C> {
    fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.emit_u8(self.role.as_u8())?;
        writer.emit_bool(self.is_kes_shard)?;
        write_field_element::<C, _>(writer, &self.encrypted_shard)?;
        write_group_element::<C, _>(writer, &self.public_nonce)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::shard_encryption::{EncryptedShard, Shard};
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
        let shard = Shard::new(EdScalar::random(rng), false, ChannelRole::Customer);
        let encrypted = EncryptedShard::<Ed25519>::encrypt_shard(&shard, &recipient_public, &mut rng);
        let decrypted_shard = encrypted.decrypt_shard(&recipient_secret);
        assert_eq!(shard.ct_eq(&decrypted_shard).unwrap_u8(), 1);
    }

    #[test]
    fn encrypt_decrypt_babyjubjub() {
        let mut rng = rand_core::OsRng;
        let shard = Shard::new(BjjScalar::random(rng), true, ChannelRole::Customer);
        let recipient_secret = BjjScalar::random(&mut rng);
        let recipient_public = BabyJubJub::generator() * &recipient_secret;
        let encrypted = EncryptedShard::<BabyJubJub>::encrypt_shard(&shard, &recipient_public, &mut rng);
        let decrypted_shard = encrypted.decrypt_shard(&recipient_secret);
        assert_eq!(shard.ct_eq(&decrypted_shard).unwrap_u8(), 1);
    }
}
