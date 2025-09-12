use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::group::GroupEncoding;
use ciphersuite::{Ciphersuite, Ed25519};
use dalek_ff_group::EdwardsPoint as XmrPoint;
use modular_frost::curve::Curve;
use modular_frost::curve::Group;
use rand_core::{CryptoRng, RngCore};
use std::ops::Mul;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DOMAIN: &[u8] = b"FVSS-EncryptedShare";

/// An encrypted witness shard $\Xi$ for a participant in the payment channel.
///
/// Each party encrypts two shards. One for the counterparty, and one for the KES.
/// If `is_kes_shard` is true, this shard is intended for the KES; and `channel_role` indicates the role of the party
/// who created the shard.
/// If `is_kes_shard` is false, this shard is intended for the counterparty; and `channel_role` indicates the role of
/// the recipient.
pub struct EncryptedShard<C: Curve> {
    encrypted_shard: C::F,
    public_nonce: C::G,
    role: ChannelRole,
    is_kes_shard: bool,
}

impl<C: Curve> HasRole for EncryptedShard<C> {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl<C: Curve> EncryptedShard<C> {
    /// Encrypt a witness shard for `recipient` using ephemeral Diffie-Hellman key exchange.
    pub fn encrypt_shard<R: RngCore + CryptoRng>(
        my_role: ChannelRole,
        is_kes_shard: bool,
        shard: &C::F,
        recipient: &C::G,
        rng: &mut R,
    ) -> Self {
        let mut nonce = C::random_nonzero_F(rng);
        let public_nonce = C::generator() * &nonce;
        let shared_point = recipient.mul(&nonce);
        let shared_secret = <C as Ciphersuite>::hash_to_F(DOMAIN, shared_point.to_bytes().as_ref());
        let encrypted_point = shared_secret + shard;
        nonce.zeroize();
        let role = if is_kes_shard { my_role } else { my_role.other() };
        Self { role, is_kes_shard, encrypted_shard: encrypted_point, public_nonce }
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

pub struct Shard<C: Curve> {
    shard: C::F,
    pub is_kes_shard: bool,
    role: ChannelRole,
}

impl Shard<Ed25519> {
    /// Verify the shard corresponds to the witness commitment, given the witness commitment point,
    /// $T_0 = \omega_0 \cdot G$, and the blinding_commitment commitment $C_0 = a \cdot G$, generated in
    /// `generate_initial_shards`.
    pub fn verify(&self, witness_commitment: &XmrPoint, blinding_commitment: &XmrPoint) -> bool {
        if self.is_kes_shard {
            self.verify_kes_shard(witness_commitment, blinding_commitment)
        } else {
            self.verify_peer_shard(witness_commitment, blinding_commitment)
        }
    }

    fn verify_peer_shard(&self, witness_commitment: &XmrPoint, blinding_commitment: &XmrPoint) -> bool {
        // peer shard is sigma_1, so verification is G * sigma_1 + (a * G + omega_0 * G) == 0
        let lhs = Ed25519::generator() * self.shard;
        let rhs = -(*blinding_commitment + witness_commitment);
        lhs == rhs
    }

    fn verify_kes_shard(&self, witness_commitment: &XmrPoint, blinding_commitment: &XmrPoint) -> bool {
        // kes shard is sigma_2, so verification is G * sigma_2 ?== 2T0 + C0
        let lhs = Ed25519::generator() * self.shard;
        let rhs = witness_commitment.double() + blinding_commitment;
        lhs == rhs
    }
}

impl<C: Curve> Shard<C> {
    pub fn shard(&self) -> &C::F {
        &self.shard
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

#[cfg(test)]
mod tests {
    use crate::crypto::shard_encryption::EncryptedShard;
    use crate::payment_channel::ChannelRole;
    use ciphersuite::Ciphersuite;
    use ciphersuite::Ed25519;
    use dalek_ff_group::{EdwardsPoint, Scalar as EdScalar};
    use grease_babyjubjub::{BabyJubJub, Scalar as BjjScalar};
    use modular_frost::curve::Field;
    use modular_frost::curve::Group;

    #[test]
    fn encrypt_decrypt_ed25519() {
        let mut rng = rand_core::OsRng;
        let shard = EdScalar::random(rng);
        let recipient_secret = EdScalar::random(&mut rng);
        let recipient_public = EdwardsPoint::generator() * &recipient_secret;
        let encrypted =
            EncryptedShard::<Ed25519>::encrypt_shard(ChannelRole::Customer, false, &shard, &recipient_public, &mut rng);
        let decrypted_shard = encrypted.decrypt_shard(&recipient_secret);
        assert_eq!(shard, decrypted_shard.shard);
    }

    #[test]
    fn encrypt_decrypt_babyjubjub() {
        let mut rng = rand_core::OsRng;
        let shard = BjjScalar::random(rng);
        let recipient_secret = BjjScalar::random(&mut rng);
        let recipient_public = BabyJubJub::generator() * &recipient_secret;
        let encrypted = EncryptedShard::<BabyJubJub>::encrypt_shard(
            ChannelRole::Customer,
            true,
            &shard,
            &recipient_public,
            &mut rng,
        );
        let decrypted_shard = encrypted.decrypt_shard(&recipient_secret);
        assert_eq!(shard, decrypted_shard.shard);
    }
}
