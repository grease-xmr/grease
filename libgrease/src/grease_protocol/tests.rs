use crate::adapter_signature::AdaptedSignature;
use crate::crypto::keys::Curve25519PublicKey;
use crate::crypto::keys::Curve25519Secret;
use crate::crypto::keys::PublicKey;
use crate::grease_protocol::utils::verify_shards;
use crate::grease_protocol::witness::generate_initial_shards;
use crate::grease_protocol::KesPoK;
use crate::multisig::{musig_2_of_2, musig_dh_viewkey, sort_pubkeys};
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::Ciphersuite;
use ciphersuite::Ed25519;
use grease_babyjubjub::{BabyJubJub, BjjPoint, Scalar as BjjScalar};
use modular_frost::curve::Field;
use rand_core::OsRng;

struct MultisigWalletInfo {
    pub customer_keys: (Curve25519Secret, Curve25519PublicKey),
    pub merchant_keys: (Curve25519Secret, Curve25519PublicKey),
    pub customer_adapt_sig: (AdaptedSignature<Ed25519>, Curve25519Secret),
    pub merchant_adapt_sig: (AdaptedSignature<Ed25519>, Curve25519Secret),
    pub sorted_pubkeys: [Curve25519PublicKey; 2],
    pub joint_private_view_key: Curve25519Secret,
    pub joint_public_view_key: Curve25519PublicKey,
    pub joint_public_spend_key: Curve25519PublicKey,
}

fn keypair() -> (Curve25519Secret, Curve25519PublicKey) {
    let mut rng = OsRng;
    Curve25519PublicKey::keypair(&mut rng)
}

fn kes_keypair() -> (BjjScalar, BjjPoint) {
    let mut rng = OsRng;
    let k = BjjScalar::random(&mut rng);
    let p = BabyJubJub::generator() * &k;
    (k, p)
}

fn simple_multisig_wallet() -> MultisigWalletInfo {
    let customer_keys = keypair();
    let merchant_keys = keypair();
    let mut pubkeys = [customer_keys.1.clone(), merchant_keys.1.clone()];
    sort_pubkeys(&mut pubkeys);
    let customer_musig_keys = musig_2_of_2(&customer_keys.0, &pubkeys).expect("customer musig keys");
    let (jprv_vk, j_pub_vk) = musig_dh_viewkey(&customer_keys.0, &merchant_keys.1);
    let joint_private_view_key = Curve25519Secret::from(jprv_vk.0);
    let joint_public_view_key = Curve25519PublicKey::from(j_pub_vk);
    let joint_public_spend_key = Curve25519PublicKey::from(customer_musig_keys.group_key());
    let mut rng = OsRng;
    // Customer signs adapter signature
    let offset = Curve25519Secret::random(&mut rng);
    let sig_adapt = AdaptedSignature::sign(customer_keys.0.as_scalar(), offset.as_scalar(), b"customer", &mut rng);
    let customer_adapt_sig = (sig_adapt, offset);
    // Merchant signs adapter signature
    let offset = Curve25519Secret::random(&mut rng);
    let sig_adapt = AdaptedSignature::sign(merchant_keys.0.as_scalar(), offset.as_scalar(), b"merchant", &mut rng);
    let merchant_adapt_sig = (sig_adapt, offset);

    MultisigWalletInfo {
        customer_keys,
        customer_adapt_sig,
        sorted_pubkeys: pubkeys,
        merchant_keys,
        merchant_adapt_sig,
        joint_private_view_key,
        joint_public_view_key,
        joint_public_spend_key,
    }
}

#[test]
#[allow(non_snake_case)]
fn channel_opening_protocol() {
    let mut rng = OsRng;
    let (kes_secret, kes_pubkey) = kes_keypair();
    // Create a new witness zero.
    let wallet_info = simple_multisig_wallet();
    // The customer splits the spend keys and produces a DLEQ proof for them.
    let w0c = wallet_info.customer_keys.0.as_scalar();
    let T0c = wallet_info.customer_keys.1.as_point();
    let customer_w0 = generate_initial_shards::<BabyJubJub, Ed25519, _>(ChannelRole::Customer, w0c, &mut rng).unwrap();
    let proof_for_merchant = customer_w0.dleq_proof();

    // The merchant splits the spend keys and produces a DLEQ proof for them.
    let w0m = wallet_info.merchant_keys.0.as_scalar();
    let T0m = wallet_info.merchant_keys.1.as_point();
    let merchant_w0 = generate_initial_shards::<BabyJubJub, Ed25519, _>(ChannelRole::Merchant, w0m, &mut rng).unwrap();
    let proof_for_customer = merchant_w0.dleq_proof();

    // Verify that the reconstructed spend keys match the original keys
    assert_eq!(
        &customer_w0.reconstruct_wallet_spend_key(),
        wallet_info.customer_keys.0.as_scalar()
    );
    assert_eq!(
        &merchant_w0.reconstruct_wallet_spend_key(),
        wallet_info.merchant_keys.0.as_scalar()
    );

    // Encrypt the shards
    let (peer_c, kes_c) = customer_w0.encrypt_shards(&T0m, &kes_pubkey, &mut rng).unwrap();
    let (peer_m, kes_m) = merchant_w0.encrypt_shards(&T0c, &kes_pubkey, &mut rng).unwrap();

    // The merchant decrypts and verifies his shard, and verifies the DLEQ proof
    let sigma1_m = peer_c.decrypt_shard(w0m);
    assert!(sigma1_m.role().is_merchant(), "Not the merchant's shard");
    assert!(
        sigma1_m.verify(&T0c, customer_w0.blinding_commitment()),
        "Merchant peer shard verification failed"
    );
    assert_eq!(sigma1_m.shard(), customer_w0.peer_shard());
    assert!(proof_for_merchant.verify(), "Merchant DLEQ proof verification failed");
    // The merchant verifies the adapter signature
    assert!(wallet_info.customer_adapt_sig.0.verify(&wallet_info.customer_keys.1.as_point(), b"customer"));

    // The customer decrypts and verifies his shard
    let sigma1_c = peer_m.decrypt_shard(w0c);
    assert!(sigma1_c.role().is_customer(), "Not the customer's shard");
    assert!(
        sigma1_c.verify(&T0m, merchant_w0.blinding_commitment()),
        "Customer peer shard verification failed"
    );
    assert_eq!(sigma1_c.shard(), merchant_w0.peer_shard());
    assert!(proof_for_customer.verify(), "Customer DLEQ proof verification failed");
    // The customer verifies the adapter signature
    assert!(wallet_info.merchant_adapt_sig.0.verify(&wallet_info.merchant_keys.1.as_point(), b"merchant"));

    // The KES decrypts her shards
    let sigma2_c = kes_c.decrypt_shard(&kes_secret);
    assert!(sigma2_c.role().is_customer(), "Not the customer's KES shard");
    let sigma2_m = kes_m.decrypt_shard(&kes_secret);
    assert!(sigma2_m.role().is_merchant(), "Not the merchant's KES shard");
    // The KES produces Proof of Knowledge proofs for its shards
    let pok_c = KesPoK::<BabyJubJub>::prove(&mut rng, &merchant_w0.foreign_kes_shard(), &kes_secret);
    let pok_m = KesPoK::<BabyJubJub>::prove(&mut rng, &customer_w0.foreign_kes_shard(), &kes_secret);

    // The merchant verifies all the bits. (We have already verified the DLEQ).
    let sigma2_m_pub = &proof_for_merchant.foreign_point;
    assert!(pok_m.verify(&sigma2_m_pub, &kes_pubkey), "Merchant KES PoK verification failed");
    // Now the merchant can reconstruct the full spend key.
    assert!(
        verify_shards(
            &wallet_info.sorted_pubkeys,
            &w0m,
            sigma1_m.shard(),
            &proof_for_merchant.xmr_point
        ),
        "Merchant shard verification against spend key failed"
    );

    // The customer verifies all the bits.
    assert!(
        pok_c.verify(&proof_for_customer.foreign_point, &kes_pubkey),
        "Merchant KES PoK verification failed"
    );
    // Now the merchant can reconstruct the full spend key.
    assert!(
        verify_shards(
            &wallet_info.sorted_pubkeys,
            &w0c,
            sigma1_c.shard(),
            &proof_for_customer.xmr_point
        ),
        "Customer shard verification against spend key failed"
    );
}
