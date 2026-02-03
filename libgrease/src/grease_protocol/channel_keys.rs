use crate::channel_id::ChannelId;
use crate::cryptography::secret_encryption::{EncryptedSecret, SecretWithRole};
use crate::cryptography::serializable_secret::SerializableSecret;
use crate::payment_channel::HasRole;
use ciphersuite::group::Group;
use ciphersuite::{group::GroupEncoding, Ciphersuite};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The ephemeral channel ID is the data structure sent by the peers to the KES that contains the encrypted shared
/// secret derived from ECDH-MC. The KES uses this information to derive the channel keys.
/// The channel ID is included for reference and to bind the secret to a specific channel.
pub struct EphemeralChannelId<C: Ciphersuite> {
    channel_id: ChannelId,
    encrypted_key: EncryptedSecret<C>,
}

/// The KES derives a unique keypair for each channel using the ephemeral channel ID sent by the customer. This struct
/// contains the derived keypair and the channel ID for reference.
/// The secret is wrapped in `Zeroizing` to ensure it is zeroed out when dropped.
pub struct ChannelKeyPair<C: Ciphersuite> {
    pub channel_id: ChannelId,
    pub secret: Zeroizing<C::F>,
    pub public: C::G,
}

/// Channel peers MUST create a unique nonce for each channel update to prevent replay attacks. This nonce is used to
/// derive a unique shared secret for the channel, the public key of which is shared with the KES to identify the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChannelNonce<C: Ciphersuite> {
    /// The secret channel nonce ($hat(k)_a or $hat(k)_b in the white paper).
    nonce: SerializableSecret<C::F>,
    /// The shared secret derived from the nonce and the peer's ephemeral public key. $kappa$, in the white paper.
    shared_secret: SerializableSecret<C::F>,
    /// The ephemeral public key, or $kappa dot.c G$ in the white paper, that is shared with the KES to identify the
    /// channel.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    pub ephemeral_pubkey: C::G,
}

impl<C: Ciphersuite> ChannelNonce<C> {
    /// Create a `ChannelNonce` from a secret nonce, the peer's ephemeral public key,
    /// and the channel ID.
    ///
    /// The shared secret is computed using ECDH-MC (Algorithm 6 in the white paper),
    /// which binds the shared secret to the specific channel ID:
    ///
    /// ```text
    /// κ = H("ECDH-MC", [nonce · peer_pubkey || channel_id])
    /// ```
    pub fn new(nonce: Zeroizing<C::F>, peer_pubkey: &C::G, channel_id: &ChannelId) -> Self {
        let shared_secret = ephemeral_channel_id::<C>(&nonce, peer_pubkey, channel_id);
        let ephemeral_pubkey = C::generator() * shared_secret;
        Self {
            nonce: SerializableSecret::from(nonce),
            shared_secret: SerializableSecret::from(shared_secret),
            ephemeral_pubkey,
        }
    }

    /// Access the raw nonce scalar.
    pub fn nonce(&self) -> &C::F {
        &self.nonce
    }

    /// Access the shared secret scalar.
    pub fn shared_secret(&self) -> &C::F {
        &self.shared_secret
    }
}

/// Derives a shared secret using ECDH-MC as specified in Algorithm 6 of the Grease white paper.
fn ephemeral_channel_id<C: Ciphersuite>(secret: &C::F, peer_pubkey: &C::G, id: &ChannelId) -> C::F {
    let shared_point = *peer_pubkey * secret;
    let msg = [shared_point.to_bytes().as_ref(), id.as_str().as_bytes()].concat();
    C::hash_to_F(b"ECDH-MC", &msg)
}

/// Encrypts the shared secret to the KES global public key, binding it to the channel ID and role.
fn encrypt_keys_to_kes<C, R, RNG>(
    channel_id: ChannelId,
    role: &R,
    mut shared_secret: C::F,
    kes_global_pubkey: &C::G,
    rng: &mut RNG,
) -> EphemeralChannelId<C>
where
    C: Ciphersuite,
    R: HasRole,
    RNG: RngCore + CryptoRng,
{
    let role = role.role();
    let secret = SecretWithRole::new(shared_secret, role);
    let domain = format!("KESChannelKey-{channel_id}");
    let encrypted_key = EncryptedSecret::encrypt(secret, kes_global_pubkey, rng, domain);
    shared_secret.zeroize();
    EphemeralChannelId { channel_id, encrypted_key }
}

/// The Customer or usually, the merchant uses this function to create an ephemeral channel ID to send to the KES.
pub fn new_ephemeral_channel_id<C, R, RNG>(
    channel_id: ChannelId,
    role: &R,
    local_ephemeral_secret: &C::F,
    peer_ephemeral_pubkey: &C::G,
    kes_global_pubkey: &C::G,
    rng: &mut RNG,
) -> EphemeralChannelId<C>
where
    C: Ciphersuite,
    R: HasRole,
    RNG: RngCore + CryptoRng,
{
    let shared_secret = ephemeral_channel_id::<C>(local_ephemeral_secret, peer_ephemeral_pubkey, &channel_id);
    encrypt_keys_to_kes::<C, R, RNG>(channel_id, role, shared_secret, kes_global_pubkey, rng)
}

/// The KES uses this function to derive a unique keypair for each channel.
///
/// This function *must* take ownership of `id` to so that the ephemeral key is discarded as per Sec 4.4 of the white
/// paper.
pub fn kes_channel_keys<C: Ciphersuite>(global_kes_secret_key: &C::F, id: EphemeralChannelId<C>) -> ChannelKeyPair<C> {
    let EphemeralChannelId { channel_id, encrypted_key } = id;
    let domain = format!("KESChannelKey-{channel_id}");
    // The role doesn't matter. Anyone can send the KES this information.
    let mut ephemeral_secret = encrypted_key.decrypt(global_kes_secret_key, domain);

    let secret = *ephemeral_secret.secret() * global_kes_secret_key;
    // Essential!  See Sec 4.4 #4 of the white paper.
    ephemeral_secret.zeroize();
    let public = C::generator() * secret;
    ChannelKeyPair { secret: Zeroizing::new(secret), public, channel_id }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphersuite::group::ff::Field;
    use ciphersuite::Ed25519;

    /// Create a valid test ChannelId (XGC prefix + 62 hex chars).
    fn test_channel_id(suffix: &str) -> ChannelId {
        use std::str::FromStr;
        // Pad/truncate the suffix to exactly 62 hex chars
        let hex_part: String = format!("{suffix:0<62}").chars().take(62).collect();
        ChannelId::from_str(&format!("XGC{hex_part}")).expect("valid test channel ID")
    }

    #[test]
    fn channel_nonce_shared_secret_uses_ecdh_mc() {
        // Verify that ChannelNonce::new() computes the shared secret using ECDH-MC
        // (binding to the channel ID), not plain ECDH.
        let mut rng = rand_core::OsRng;
        let nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let peer_secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let peer_pubkey = Ed25519::generator() * peer_secret;
        let channel_id = test_channel_id("aa");

        let cn = ChannelNonce::<Ed25519>::new(nonce.clone(), &peer_pubkey, &channel_id);

        // Manually compute expected ECDH-MC shared secret
        let shared_point = peer_pubkey * *nonce;
        let msg = [shared_point.to_bytes().as_ref(), channel_id.as_str().as_bytes()].concat();
        let expected = Ed25519::hash_to_F(b"ECDH-MC", &msg);

        assert_eq!(*cn.shared_secret(), expected, "shared secret must use ECDH-MC");
    }

    #[test]
    fn channel_nonce_shared_secret_is_not_plain_ecdh() {
        // Ensure the shared secret differs from a plain ECDH (without channel ID binding).
        use crate::cryptography::ecdh::ecdh;
        let mut rng = rand_core::OsRng;
        let nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let peer_secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let peer_pubkey = Ed25519::generator() * peer_secret;
        let channel_id = test_channel_id("bb");

        let cn = ChannelNonce::<Ed25519>::new(nonce.clone(), &peer_pubkey, &channel_id);
        let plain_ecdh = ecdh::<Ed25519, _>(&nonce, &peer_pubkey, b"ChannelNonceSharedSecret");

        assert_ne!(
            *cn.shared_secret(),
            *plain_ecdh,
            "ECDH-MC shared secret must differ from plain ECDH"
        );
    }

    #[test]
    fn channel_nonce_different_channel_ids_produce_different_secrets() {
        let mut rng = rand_core::OsRng;
        let nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let peer_secret = <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let peer_pubkey = Ed25519::generator() * peer_secret;

        let cn_a = ChannelNonce::<Ed25519>::new(nonce.clone(), &peer_pubkey, &test_channel_id("aa"));
        let cn_b = ChannelNonce::<Ed25519>::new(nonce.clone(), &peer_pubkey, &test_channel_id("bb"));

        assert_ne!(
            *cn_a.shared_secret(),
            *cn_b.shared_secret(),
            "different channel IDs must produce different shared secrets"
        );
    }

    #[test]
    fn channel_nonce_is_symmetric() {
        // Both parties (with swapped nonce/pubkey) should derive the same shared secret.
        let mut rng = rand_core::OsRng;
        let alice_nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let bob_nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let alice_pubkey = Ed25519::generator() * *alice_nonce;
        let bob_pubkey = Ed25519::generator() * *bob_nonce;
        let channel_id = test_channel_id("cc");

        let alice_cn = ChannelNonce::<Ed25519>::new(alice_nonce, &bob_pubkey, &channel_id);
        let bob_cn = ChannelNonce::<Ed25519>::new(bob_nonce, &alice_pubkey, &channel_id);

        assert_eq!(
            *alice_cn.shared_secret(),
            *bob_cn.shared_secret(),
            "ECDH-MC shared secret must be symmetric"
        );
    }

    #[test]
    fn channel_nonce_ephemeral_pubkey_matches_nonce() {
        let mut rng = rand_core::OsRng;
        let nonce = Zeroizing::new(<Ed25519 as Ciphersuite>::F::random(&mut rng));
        let peer_pubkey = Ed25519::generator() * <Ed25519 as Ciphersuite>::F::random(&mut rng);
        let channel_id = test_channel_id("dd");

        let cn = ChannelNonce::<Ed25519>::new(nonce.clone(), &peer_pubkey, &channel_id);

        let expected_pubkey = Ed25519::generator() * *cn.shared_secret();
        assert_eq!(
            cn.ephemeral_pubkey, expected_pubkey,
            "ephemeral pubkey should be shared_secret * G"
        );
    }
}
