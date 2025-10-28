use crate::adapter_signature::AdaptedSignature;
use crate::crypto::common_types::HashCommitment256;
use crate::crypto::keys::Curve25519PublicKey;
use crate::crypto::keys::Curve25519Secret;
use crate::crypto::keys::PublicKey;
use crate::crypto::pok::KesPoK;
use crate::crypto::witness::{InitialShards, PublicShardInfo};
use crate::crypto::Commit;
use crate::grease_protocol::open_channel::{
    AdapterSignatureHandler, CustomerOpenProtocol, HasPublicKey, HasSecretKey, MerchantOpenProtocol,
    MultisigWalletKeys, OpenProtocolError, ReadSharedWalletInfo, ShardHandler,
};
use crate::grease_protocol::utils::verify_shards;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::{XmrPoint, XmrScalar};
use blake2::Blake2b512;
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use ciphersuite::Ed25519;
use flexible_transcript::{DigestTranscript, SecureDigest, Transcript};
use grease_babyjubjub::{BabyJubJub, BjjPoint, Scalar as BjjScalar};
use modular_frost::curve::Field;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::io::{Read, Write};
use subtle::ConstantTimeEq;

struct MultisigWalletKey {
    pub role: ChannelRole,
    pub witness: Curve25519Secret,
    pub public_key: Curve25519PublicKey,
}

impl HasRole for MultisigWalletKey {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl Writable for MultisigWalletKey {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.emit_bool(self.role.is_merchant())?;
        writer.emit_slice(self.public_key.as_point().compress().as_bytes())?;
        writer.emit_slice(self.witness.as_scalar().as_bytes())
    }
}

#[derive(Clone)]
struct SharedWalletInfo {
    pub role: ChannelRole,
    pub public_key: Curve25519PublicKey,
}

impl HasPublicKey for SharedWalletInfo {
    fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }
}

impl ReadSharedWalletInfo for SharedWalletInfo {
    fn read<R: Read>(reader: &mut R) -> Result<Self, OpenProtocolError> {
        let is_merchant = reader
            .read_bool()
            .map_err(|e| OpenProtocolError::InvalidDataFromPeer(format!("Expected hasRole as a bool. {e}")))?;
        let role = if is_merchant { ChannelRole::Merchant } else { ChannelRole::Customer };
        let mut buf = [0u8; 32];
        reader
            .read_exact(&mut buf)
            .map_err(|e| OpenProtocolError::InvalidDataFromPeer(format!("Expected public key bytes. {e}")))?;
        let point = XmrPoint::from_bytes(&buf)
            .into_option()
            .ok_or_else(|| OpenProtocolError::InvalidDataFromPeer("Expected public key point.".into()))?;
        let public_key = Curve25519PublicKey::from(point);
        Ok(SharedWalletInfo { role, public_key })
    }
}

impl HasRole for SharedWalletInfo {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl Writable for SharedWalletInfo {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.emit_bool(self.role.is_merchant())?;
        writer.emit_slice(self.public_key.as_point().compress().as_bytes())
    }
}

impl<D: SecureDigest + Send + Clone> Commit<D> for SharedWalletInfo {
    type Committed = HashCommitment256<D>;
    type Transcript = DigestTranscript<D>;

    fn commit(&self) -> Self::Committed {
        let mut transcript = Self::Transcript::new(b"pubkey-t-m");
        transcript.append_message(b"role", self.role);
        transcript.append_message(b"my_pubkey", self.public_key.to_compressed().as_bytes());
        let commitment = transcript.challenge(b"merchant-public-key-commitment");
        let mut data = [0u8; 32];
        // The compiler guarantees that the output size of the hash function is at least 32 bytes.
        data.copy_from_slice(&commitment[0..32]);
        HashCommitment256::new(data)
    }
}

impl MultisigWalletKeys for MultisigWalletKey {
    type SharedWalletInfo = SharedWalletInfo;

    fn new<R: RngCore + CryptoRng>(rng: &mut R, role: ChannelRole) -> Self {
        let (witness, public_key) = Curve25519PublicKey::keypair(rng);
        MultisigWalletKey { role, witness, public_key }
    }

    fn secret(&self) -> &Curve25519Secret {
        &self.witness
    }

    fn public_key(&self) -> &Curve25519PublicKey {
        &self.public_key
    }

    fn shared_info(&self) -> Self::SharedWalletInfo {
        SharedWalletInfo { role: self.role, public_key: self.public_key.clone() }
    }
}

fn kes_keypair() -> (BjjScalar, BjjPoint) {
    let mut rng = OsRng;
    let k = BjjScalar::random(&mut rng);
    let p = BabyJubJub::generator() * &k;
    (k, p)
}

struct MerchantChannelOpener {
    wallet_info: MultisigWalletKey,
    customer_info: Option<SharedWalletInfo>,
    kes_pubkey: Option<BjjPoint>,
    initial_shards: Option<InitialShards<BabyJubJub, Ed25519>>,
    offset: Option<XmrScalar>,
}

impl HasRole for MerchantChannelOpener {
    fn role(&self) -> ChannelRole {
        ChannelRole::Merchant
    }
}

impl ShardHandler<BabyJubJub, Blake2b512> for MerchantChannelOpener {
    type SharedWalletInfo = SharedWalletInfo;

    fn shared_wallet_info(&self) -> Self::SharedWalletInfo {
        self.wallet_info.shared_info()
    }

    fn peer_shared_wallet_info(&self) -> Option<&Self::SharedWalletInfo> {
        self.customer_info.as_ref()
    }

    fn set_shared_wallet_info(&mut self, info: Self::SharedWalletInfo) {
        self.customer_info = Some(info);
    }

    fn set_initial_shards(&mut self, shards: InitialShards<BabyJubJub, Ed25519>) {
        self.initial_shards = Some(shards);
    }

    fn initial_shards(&self) -> Option<&InitialShards<BabyJubJub, Ed25519>> {
        self.initial_shards.as_ref()
    }

    fn set_kes_pubkey(&mut self, kes_pubkey: BjjPoint) {
        self.kes_pubkey = Some(kes_pubkey);
    }

    fn kes_pubkey(&self) -> Option<&BjjPoint> {
        self.kes_pubkey.as_ref()
    }
}

impl HasSecretKey for MerchantChannelOpener {
    fn secret_key(&self) -> &Curve25519Secret {
        &self.wallet_info.witness
    }
}

impl AdapterSignatureHandler for MerchantChannelOpener {
    fn generate_adapter_signature_offset<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        let offset = XmrScalar::random(rng);
        self.offset = Some(offset);
    }

    fn adapter_signature_offset(&self) -> Option<&XmrScalar> {
        self.offset.as_ref()
    }
}

impl MerchantOpenProtocol<BabyJubJub, Blake2b512> for MerchantChannelOpener {
    type WalletKeys = MultisigWalletKey;

    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = MultisigWalletKey::new(rng, ChannelRole::Merchant);
        Self { wallet_info: key, customer_info: None, kes_pubkey: None, initial_shards: None, offset: None }
    }

    fn wallet_info(&self) -> &Self::WalletKeys {
        &self.wallet_info
    }
}

struct CustomerChannelOpener {
    wallet_info: MultisigWalletKey,
    merchant_commitments: Option<HashCommitment256<Blake2b512>>,
    merchant_info: Option<SharedWalletInfo>,
    initial_shards: Option<InitialShards<BabyJubJub, Ed25519>>,
    kes_pubkey: Option<BjjPoint>,
    offset: Option<XmrScalar>,
}

impl HasRole for CustomerChannelOpener {
    fn role(&self) -> ChannelRole {
        ChannelRole::Customer
    }
}

impl HasSecretKey for CustomerChannelOpener {
    fn secret_key(&self) -> &Curve25519Secret {
        &self.wallet_info.witness
    }
}

impl ShardHandler<BabyJubJub, Blake2b512> for CustomerChannelOpener {
    type SharedWalletInfo = SharedWalletInfo;

    fn shared_wallet_info(&self) -> Self::SharedWalletInfo {
        self.wallet_info.shared_info()
    }

    fn peer_shared_wallet_info(&self) -> Option<&Self::SharedWalletInfo> {
        self.merchant_info.as_ref()
    }

    fn set_shared_wallet_info(&mut self, info: Self::SharedWalletInfo) {
        self.merchant_info = Some(info);
    }

    fn set_initial_shards(&mut self, shards: InitialShards<BabyJubJub, Ed25519>) {
        self.initial_shards = Some(shards);
    }

    fn initial_shards(&self) -> Option<&InitialShards<BabyJubJub, Ed25519>> {
        self.initial_shards.as_ref()
    }

    fn set_kes_pubkey(&mut self, kes_pubkey: BjjPoint) {
        self.kes_pubkey = Some(kes_pubkey);
    }

    fn kes_pubkey(&self) -> Option<&BjjPoint> {
        self.kes_pubkey.as_ref()
    }
}

impl AdapterSignatureHandler for CustomerChannelOpener {
    fn generate_adapter_signature_offset<R: RngCore + CryptoRng>(&mut self, rng: &mut R) {
        self.offset = Some(XmrScalar::random(rng));
    }

    fn adapter_signature_offset(&self) -> Option<&XmrScalar> {
        self.offset.as_ref()
    }
}

impl CustomerOpenProtocol<BabyJubJub, Blake2b512> for CustomerChannelOpener {
    type WalletKeys = MultisigWalletKey;

    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = MultisigWalletKey::new(rng, ChannelRole::Customer);
        Self {
            wallet_info: key,
            merchant_commitments: None,
            merchant_info: None,
            initial_shards: None,
            kes_pubkey: None,
            offset: None,
        }
    }

    fn read_wallet_commitment<R: Read + ?Sized>(&mut self, reader: &mut R) -> Result<(), OpenProtocolError> {
        let mut commitment = [0u8; 32];
        reader
            .read_exact(&mut commitment)
            .map_err(|e| OpenProtocolError::InvalidDataFromPeer(format!("Expected commitment bytes. {e}")))?;
        self.merchant_commitments = Some(HashCommitment256::new(commitment));
        Ok(())
    }

    fn wallet_info(&self) -> &Self::WalletKeys {
        &self.wallet_info
    }

    fn verify_merchant_public_key(&self) -> Result<(), OpenProtocolError> {
        let info = self
            .merchant_info
            .as_ref()
            .ok_or_else(|| OpenProtocolError::MissingInformation("Merchant shared wallet info".into()))?;
        let commitment = self
            .merchant_commitments
            .as_ref()
            .ok_or_else(|| OpenProtocolError::MissingInformation("Merchant public key commitment".into()))?;
        match info.verify(commitment) {
            true => Ok(()),
            false => Err(OpenProtocolError::InvalidDataFromPeer(
                "Merchant public key does not match commitment".into(),
            )),
        }
    }
}

#[test]
#[allow(non_snake_case)]
fn channel_opening_protocol() {
    let mut rng = OsRng;
    let (kes_secret, kes_pubkey) = kes_keypair();
    // Merchant starts a new "Open Channel" protocol
    let mut merchant_protocol = MerchantChannelOpener::new(&mut rng);
    let commitment = merchant_protocol.commit_to_shared_wallet_info();
    // The merchant needs to commit to his pubkey before seeing the customer's pubkey
    // ---> Commitment to customer
    let data_for_customer = commitment.serialize();

    // <--- Customer receives commitment from merchant
    let mut customer_protocol = CustomerChannelOpener::new(&mut rng);
    let mut reader = &data_for_customer[..];
    customer_protocol.read_wallet_commitment(&mut reader).expect("Expected merchant commitment");

    // ---> Customer sends pubkey to merchant
    let data_for_merchant = customer_protocol.shared_wallet_info().serialize();
    // <--- Merchant receives pubkey from customer
    let mut reader = &data_for_merchant[..];
    merchant_protocol.read_shared_wallet_info(&mut reader).expect("Expected customer shared info");

    // ---> Merchant sends wallet pubkey to customer
    let data_for_customer = merchant_protocol.shared_wallet_info().serialize();

    // <--- Customer gets merchant's public key commitment.
    let mut reader = &data_for_customer[..];
    customer_protocol.read_shared_wallet_info(&mut reader).expect("Expected merchant shared info");
    // The customer splits the spend keys and produces a DLEQ proof for them.
    customer_protocol.generate_initial_shards::<Ed25519, _>(&mut rng).unwrap();
    let customer_w0 = customer_protocol.initial_shards().unwrap();
    // Test only: Verify that the reconstructed spend keys match the original keys
    assert_eq!(
        &customer_w0.reconstruct_wallet_spend_key(),
        customer_protocol.wallet_info.secret().as_scalar()
    );
    let merchant_info = customer_protocol.peer_shared_wallet_info().unwrap();
    let peer_shard_info =
        customer_w0.generate_public_shard_info(&merchant_info.public_key.as_point(), &kes_pubkey, &mut rng);
    // Encrypt the shards
    customer_protocol.set_kes_pubkey(kes_pubkey);
    customer_protocol.generate_adapter_signature_offset(&mut rng);
    let adapted_c = customer_protocol.new_adapter_signature(&mut rng).expect("Expected customer new adapter signature");
    // ---> Send (DLEQ proof, peer_c, kes_c, adapted_c) to merchant
    let shard_data = peer_shard_info.serialize();
    let adapted_c_data = adapted_c.serialize();

    // <--- Merchant receives (DLEQ proof, peer_c, kes_c, adapted_c) from customer
    let peer_shard_info = PublicShardInfo::<BabyJubJub, Ed25519>::read(&mut &shard_data[..])
        .expect("Expected peer_shard_info deserialization");
    // Merchant verifies the shard
    let sigma1_m = peer_shard_info
        .decrypt_and_verify(merchant_protocol.secret_key().as_scalar())
        .expect("Expected merchant decrypt and verify shard");

    assert!(sigma1_m.role().is_merchant(), "Not the merchant's shard");
    // Test only assertion:
    assert_eq!(
        sigma1_m.ct_eq(customer_protocol.initial_shards().unwrap().peer_shard()).unwrap_u8(),
        1
    );
    // Merchant verifies the adapter signature
    let adapted_c =
        AdaptedSignature::<Ed25519>::read(&mut &adapted_c_data[..]).expect("Expected adapted_c deserialization");
    assert!(
        adapted_c.verify(
            &merchant_protocol.peer_shared_wallet_info().unwrap().public_key.as_point(),
            merchant_protocol.adapter_signature_message()
        ),
        "Expected adapted signature verification"
    );
    // Merchant verifies the dleq proof
    let (pub_shard_c, sigma2_c_pub) = peer_shard_info.verify_dleq_proof().expect("Expected DLEQ proof verification");
    let kes_c = peer_shard_info.kes_shard().clone();
    // The merchant splits the spend keys and produces a DLEQ proof for them.
    merchant_protocol.generate_initial_shards::<Ed25519, _>(&mut rng).unwrap();
    let merchant_w0 = merchant_protocol.initial_shards().unwrap();
    let merchant_shard_for_customer = merchant_w0.peer_shard().clone();
    let kes_shard_m = merchant_w0.foreign_kes_shard().clone();
    // Test only: Verify that the reconstructed spend keys match the original keys
    assert_eq!(
        &merchant_w0.reconstruct_wallet_spend_key(),
        merchant_protocol.wallet_info.witness.as_scalar()
    );
    // Encrypt the shards
    let shard_info = merchant_w0.generate_public_shard_info(
        &merchant_protocol.peer_shared_wallet_info().unwrap().public_key.as_point(),
        &kes_pubkey,
        &mut rng,
    );
    merchant_protocol.generate_adapter_signature_offset(&mut rng);
    let adapted_m = merchant_protocol.new_adapter_signature(&mut rng).expect("Expected merchant new adapter signature");
    // ---> Send (DLEQ proof, peer_m, kes_m, adapted_m, pubkey_m) to customer
    let shard_data = shard_info.serialize();
    let adapted_m_data = adapted_m.serialize();
    // ---> Send (kes_m, kes_c) to KES
    let kes_m = shard_info.kes_shard().clone();

    // <--- Customer receives (DLEQ proof, peer_m, kes_m, adapted_m, pubkey_m) from merchant
    let shard_data_m = PublicShardInfo::<BabyJubJub, Ed25519>::read(&mut &shard_data[..])
        .expect("Expected peer_shard_info deserialization");
    let adapted_m =
        AdaptedSignature::<Ed25519>::read(&mut &adapted_m_data[..]).expect("Expected adapted_m deserialization");
    // Customer verifies merchant's pubkey against the commitment
    assert!(customer_protocol.verify_merchant_public_key().is_ok());
    // The customer decrypts and verifies his shard
    let sigma1_c = shard_data_m
        .decrypt_and_verify(customer_protocol.wallet_info.secret().as_scalar())
        .expect("Expected customer decrypt and verify shard");
    let (pub_shard_m, sigma2_m_pub) = shard_data_m.verify_dleq_proof().expect("Expected DLEQ proof verification");
    assert!(sigma1_c.role().is_customer(), "Not the customer's shard");
    assert_eq!(sigma1_c.ct_eq(&merchant_shard_for_customer).unwrap_u8(), 1);
    // The customer verifies the adapter signature
    assert!(adapted_m.verify(
        &customer_protocol.peer_shared_wallet_info().unwrap().public_key().as_point(),
        customer_protocol.adapter_signature_message()
    ));
    // <--- KES receives (kes_m, kes_c) from merchant
    // The KES decrypts her shards
    assert!(kes_c.is_kes_shard());
    assert!(kes_m.is_kes_shard());
    let sigma2_c = kes_c.decrypt_shard(&kes_secret);
    let sigma2_m = kes_m.decrypt_shard(&kes_secret);
    assert!(sigma2_c.role().is_customer(), "Not the customer's KES shard");
    assert!(sigma2_m.role().is_merchant(), "Not the merchant's KES shard");
    // // The KES produces Proof of Knowledge proofs for its shards
    let pok_m = KesPoK::<BabyJubJub>::prove(&mut rng, &kes_shard_m.shard(), &kes_secret);
    let customer_w0 = customer_protocol.initial_shards().unwrap();
    let pok_c = KesPoK::<BabyJubJub>::prove(&mut rng, &customer_w0.foreign_kes_shard().shard(), &kes_secret);
    let pok_c_data = pok_c.serialize();
    let pok_m_data = pok_m.serialize();
    // --> Send (pok_m, pok_c) to merchant (and customer)
    //
    // <--- Customer receives (pok_m, pok_c) from KES
    let pok_c = KesPoK::<BabyJubJub>::read(&mut &pok_c_data[..]).expect("Expected pok_c deserialization");
    let pok_m = KesPoK::<BabyJubJub>::read(&mut &pok_m_data[..]).expect("Expected pok_m deserialization");
    // The merchant verifies all the bits. (We have already verified the DLEQ).
    assert!(pok_c.verify(&sigma2_c_pub, &kes_pubkey), "Merchant KES PoK verification failed");
    assert!(pok_m.verify(&sigma2_m_pub, &kes_pubkey), "Merchant KES PoK verification failed");
    // Now the merchant can reconstruct the full spend key.
    let pubkeys = vec![
        merchant_protocol.wallet_info.public_key().clone(),
        customer_protocol.wallet_info.public_key().clone(),
    ];
    assert!(
        verify_shards(
            &pubkeys,
            &merchant_protocol.secret_key().as_scalar(),
            sigma1_m.shard(),
            &pub_shard_c
        ),
        "Merchant shard verification against spend key failed"
    );

    // The customer verifies all the bits.
    assert!(pok_c.verify(&sigma2_c_pub, &kes_pubkey), "Merchant KES PoK verification failed");
    // Now the customer can reconstruct the full spend key.
    assert!(
        verify_shards(
            &pubkeys,
            customer_protocol.secret_key().as_scalar(),
            sigma1_c.shard(),
            &pub_shard_m
        ),
        "Customer shard verification against spend key failed"
    );
}
