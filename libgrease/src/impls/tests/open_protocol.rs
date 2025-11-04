use crate::cryptography::adapter_signature::AdaptedSignature;
use crate::cryptography::dleq::{Dleq, DleqProof};
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKeyCommitment};
use crate::cryptography::pok::KesPoK;
use crate::cryptography::secret_encryption::EncryptedSecret;
use crate::grease_protocol::adapter_signature::AdapterSignatureHandler;
use crate::grease_protocol::kes::{KesClient, KesClientError, KesSecrets};
use crate::grease_protocol::multisig_wallet::{HasPublicKey, HasSecretKey, LinkedMultisigWallets};
use crate::grease_protocol::open_channel::{
    CustomerOpenProtocol, MerchantOpenProtocol, OpenProtocol, OpenProtocolError, PeerInfo,
};
use crate::grease_protocol::utils::Readable;
use crate::impls::multisig::MultisigWalletKeyRing;
use crate::payment_channel::{ChannelRole, HasRole};
use blake2::Blake2b512;
use ciphersuite::Ciphersuite;
use ciphersuite::Ed25519;
use grease_babyjubjub::{BabyJubJub, BjjPoint, Scalar as BjjScalar};
use log::info;
use modular_frost::curve::Field;
use modular_frost::sign::Writable;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::io::Read;

fn kes_keypair() -> (BjjScalar, BjjPoint) {
    let mut rng = OsRng;
    let k = BjjScalar::random(&mut rng);
    let p = BabyJubJub::generator() * &k;
    (k, p)
}

struct ChannelOpenData {
    wallet_keyring: MultisigWalletKeyRing,
    kes_secrets: Option<KesSecrets<BabyJubJub>>,
    peer_dleq_proof: Option<DleqProof<BabyJubJub, Ed25519>>,
    peer_adapted_sig: Option<AdaptedSignature<Ed25519>>,
}

impl HasSecretKey for ChannelOpenData {
    fn secret_key(&self) -> Curve25519Secret {
        self.wallet_keyring.partial_spend_key.clone()
    }
}

impl HasPublicKey for ChannelOpenData {
    fn public_key(&self) -> Curve25519PublicKey {
        self.wallet_keyring.public_key()
    }
}

impl PeerInfo<BabyJubJub> for ChannelOpenData {
    fn peer_dleq_proof(&self) -> Option<&DleqProof<BabyJubJub, Ed25519>> {
        self.peer_dleq_proof.as_ref()
    }

    fn peer_public_key(&self) -> Option<Curve25519PublicKey> {
        self.wallet_keyring.peer_public_key().ok()
    }

    fn peer_adapted_signature(&self) -> Option<&AdaptedSignature<Ed25519>> {
        self.peer_adapted_sig.as_ref()
    }
}

impl HasRole for ChannelOpenData {
    fn role(&self) -> ChannelRole {
        self.wallet_keyring.role()
    }
}

impl OpenProtocol<BabyJubJub, Blake2b512> for ChannelOpenData {
    type MultisigWallet = MultisigWalletKeyRing;
    type KesClient = KesSecrets<BabyJubJub>;

    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole) -> Self {
        let key = MultisigWalletKeyRing::random(rng, role);
        Self { wallet_keyring: key, kes_secrets: None, peer_dleq_proof: None, peer_adapted_sig: None }
    }

    fn initialize_kes_client<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        kes_pubkey: BjjPoint,
    ) -> Result<(), OpenProtocolError> {
        let kes_secrets = KesSecrets::generate(rng, kes_pubkey, self.role()).map_err(|e| match e {
            KesClientError::InvalidKesPublicKey => OpenProtocolError::InvalidKesPublicKey,
            KesClientError::DleqProofGenerationError(e) => OpenProtocolError::AdapterSigOffsetError(e),
        })?;
        self.kes_secrets = Some(kes_secrets);
        Ok(())
    }

    fn kes_client(&self) -> Result<&Self::KesClient, OpenProtocolError> {
        let client = self
            .kes_secrets
            .as_ref()
            .ok_or_else(|| OpenProtocolError::MissingInformation("initialize_kes_client has not been called".into()))?;
        Ok(client)
    }

    fn wallet(&self) -> &Self::MultisigWallet {
        &self.wallet_keyring
    }

    fn wallet_mut(&mut self) -> &mut Self::MultisigWallet {
        &mut self.wallet_keyring
    }

    fn set_peer_adapted_signature(&mut self, adapted_signature: AdaptedSignature<Ed25519>) {
        self.peer_adapted_sig = Some(adapted_signature);
    }

    fn set_peer_dleq_proof(&mut self, dleq_proof: DleqProof<BabyJubJub, Ed25519>) {
        self.peer_dleq_proof = Some(dleq_proof);
    }
}

impl CustomerOpenProtocol<BabyJubJub, Blake2b512> for ChannelOpenData {
    fn read_wallet_commitment<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let commitment =
            PublicKeyCommitment::read(reader).map_err(|e| OpenProtocolError::InvalidCommitment(e.to_string()))?;
        self.wallet_keyring.set_peer_public_key_commitment(commitment);
        Ok(())
    }

    fn verify_merchant_public_key(&self) -> Result<(), OpenProtocolError> {
        self.wallet_keyring.verify_peer_public_key()?;
        Ok(())
    }
}

impl MerchantOpenProtocol<BabyJubJub, Blake2b512> for ChannelOpenData {}

fn setup_new_multisig_wallets(merchant: &mut ChannelOpenData, customer: &mut ChannelOpenData) {
    let commitment = merchant.wallet().commit_to_public_key();
    // The merchant needs to commit to his pubkey before seeing the customer's pubkey
    // ---> Commitment to customer
    let data_for_customer = commitment.serialize();

    // <--- Customer receives commitment from merchant
    let mut reader = &data_for_customer[..];
    customer.read_wallet_commitment(&mut reader).expect("Expected merchant commitment");

    // ---> Customer sends pubkey to merchant
    let data_for_merchant = customer.wallet().shared_public_key().serialize();
    // <--- Merchant receives pubkey from customer
    merchant.read_peer_shared_public_key(&mut &data_for_merchant[..]).expect("Expected customer shared info");

    // ---> Merchant sends wallet pubkey to customer
    let data_for_customer = merchant.wallet().shared_public_key().serialize();
    // <--- Customer gets merchant's public key.
    customer.read_peer_shared_public_key(&mut &data_for_customer[..]).expect("Expected merchant shared info");
    // Verify that the received public key matches the commitment
    customer.verify_merchant_public_key().expect("Expected merchant public key verification");
}

fn wallet_transaction_protocol(_m: &mut ChannelOpenData, _c: &mut ChannelOpenData) {
    // We're not going to do anything in this test. This is just a marker to indicate where the TX negotiation goes.
}

#[test]
fn channel_opening_protocol() {
    let _ = env_logger::try_init();
    let mut rng = OsRng;
    let (kes_secret, kes_pubkey) = kes_keypair();
    // Merchant starts a new "Open Channel" protocol
    let mut merchant_protocol = ChannelOpenData::new(&mut rng, ChannelRole::Merchant);
    let mut customer_protocol = ChannelOpenData::new(&mut rng, ChannelRole::Customer);
    info!("Customer pubkey: {}", customer_protocol.public_key().as_hex());
    info!("Merchant pubkey: {}", merchant_protocol.public_key().as_hex());
    setup_new_multisig_wallets(&mut merchant_protocol, &mut customer_protocol);
    // In the P2P protocol, we would check that the joint Monero address matches, but we don't have the view key in
    // this test.
    wallet_transaction_protocol(&mut merchant_protocol, &mut customer_protocol);
    // Encrypt the ω0 adapters
    customer_protocol.initialize_kes_client(&mut rng, kes_pubkey).expect("customer kes init");
    let adapted_c = customer_protocol
        .kes_client()
        .unwrap()
        .new_adapter_signature(&customer_protocol.secret_key(), &mut rng)
        .expect(
            "Expected customer new adapter \
        signature",
        );
    let proof_c = customer_protocol.kes_client().unwrap().dleq_proof();
    let enrypted_w0c = customer_protocol.kes_client().unwrap().encrypt_to_kes(&mut rng);
    // ---> Send (DLEQ proof, (ŝc, Qc, Rc), Xc to merchant
    let sig_data = adapted_c.serialize();
    let proof_data = proof_c.serialize();
    let encrypted_w0c_data = enrypted_w0c.serialize();

    // <--- Merchant receives (adapted_c, DLEQ proof, X_c) from customer
    // Merchant verifies the adapter signature (and DLEQ proof, and Qs match)
    merchant_protocol.read_peer_adapted_signature(&mut &sig_data[..]).expect("valid sig data");
    merchant_protocol.read_peer_dleq_proof(&mut &proof_data[..]).expect("valid dleq proof");
    merchant_protocol.initialize_kes_client(&mut rng, kes_pubkey).expect("merchant kes init");
    let kes_client = merchant_protocol.kes_client().unwrap();
    let msg = kes_client.adapter_signature_message();
    merchant_protocol.verify_adapter_sig_offset(msg).expect("verify adapter sig");

    // The merchant creates a new adapter signature produces a DLEQ proof.
    let adapted_m =
        kes_client.new_adapter_signature(&merchant_protocol.secret_key(), &mut rng).expect("to generate adapter sig");
    let dleq_proof_m = kes_client.dleq_proof();
    let encrypted_w0m = kes_client.encrypt_to_kes(&mut rng);

    let proof_data = dleq_proof_m.serialize();
    let sig_data = adapted_m.serialize();
    let encrypted_w0m_data = encrypted_w0m.serialize();

    // ---> Send (DLEQ proof, peer_m, kes_m, adapted_m, pubkey_m) to customer.
    customer_protocol.read_peer_adapted_signature(&mut &sig_data[..]).expect("valid adapter sig");
    customer_protocol.read_peer_dleq_proof(&mut &proof_data[..]).expect("valid dleq proof");
    // Verify the adapter signature offset
    let kes_client = customer_protocol.kes_client().unwrap();
    let msg = kes_client.adapter_signature_message();
    customer_protocol.verify_adapter_sig_offset(msg).expect("verify merchant adapter sig");

    // <--- KES receives (kes_m, kes_c) from merchant
    // The KES decrypts her shards
    let xi_c = EncryptedSecret::<BabyJubJub>::read(&mut &encrypted_w0c_data[..]).expect("kes to read w0c");
    let xi_m = EncryptedSecret::<BabyJubJub>::read(&mut &encrypted_w0m_data[..]).expect("kes to read w0m");
    let w0c = xi_c.decrypt(&kes_secret, KesSecrets::<BabyJubJub>::domain_separation_tag());
    let w0m = xi_m.decrypt(&kes_secret, KesSecrets::<BabyJubJub>::domain_separation_tag());
    assert!(w0c.role().is_customer(), "Not the customer's KES shard");
    assert!(w0m.role().is_merchant(), "Not the merchant's KES shard");
    // // The KES produces Proof of Knowledge proofs for its shards
    let pok_m = KesPoK::<BabyJubJub>::prove(&mut rng, w0m.secret(), &kes_secret);
    let pok_c = KesPoK::<BabyJubJub>::prove(&mut rng, &w0c.secret(), &kes_secret);
    let pok_c_data = pok_c.serialize();
    let pok_m_data = pok_m.serialize();
    // --> Send (pok_m, pok_c) to merchant (and customer)

    // <--- Customer receives (pok_m, pok_c) from KES
    let pok_c = KesPoK::<BabyJubJub>::read(&mut &pok_c_data[..]).expect("Expected pok_c deserialization");
    let pok_m = KesPoK::<BabyJubJub>::read(&mut &pok_m_data[..]).expect("Expected pok_m deserialization");
    // The merchant verifies all the bits. (We have already verified the DLEQ).
    let kes_client = merchant_protocol.kes_client().unwrap();
    assert!(
        pok_m.verify(&kes_client.dleq_proof().foreign_point, &kes_pubkey),
        "Merchant KES PoK verification failed"
    );
    assert!(
        pok_c.verify(&merchant_protocol.peer_dleq_proof.unwrap().foreign_point, &kes_pubkey),
        "Customer KES PoK verification failed"
    );

    // The customer verifies all the bits.
    assert!(
        pok_c.verify(&customer_protocol.kes_client().unwrap().dleq_proof().foreign_point, &kes_pubkey),
        "Customer KES PoK verification failed"
    );
    assert!(
        pok_m.verify(&customer_protocol.peer_dleq_proof().unwrap().foreign_point, &kes_pubkey),
        "Customer KES PoK verification failed"
    );
}
