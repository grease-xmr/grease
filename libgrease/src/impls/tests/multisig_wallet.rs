use crate::amount::MoneroAmount;
use crate::cryptography::adapter_signature::SchnorrSignature;
use crate::cryptography::keys::PublicKeyCommitment;
use crate::grease_protocol::multisig_wallet::{
    LinkedMultisigWallets, MoneroPayment, MultisigTransaction, MultisigTxError, MultisigWalletError, SharedPublicKey,
};
use crate::grease_protocol::utils::Readable;
use crate::impls::multisig::MultisigWalletKeyRing;
use crate::payment_channel::{ChannelRole, HasRole};
use ciphersuite::Ed25519;
use modular_frost::sign::Writable;
use monero::Address;
use rand_core::{CryptoRng, RngCore};
use std::io::Write;

pub struct WritableString(String);

impl WritableString {
    pub fn new<S: Into<String>>(v: S) -> Self {
        Self(v.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Writable for WritableString {
    fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.0.as_bytes())
    }
}

pub struct TestWallet {
    role: ChannelRole,
}

pub struct MockPayment {
    amount: MoneroAmount,
    address: Address,
}

impl HasRole for TestWallet {
    fn role(&self) -> ChannelRole {
        self.role
    }
}

impl MoneroPayment for MockPayment {
    fn new<A: Into<Address>, V: Into<MoneroAmount>>(recipient: A, amount: V) -> Self {
        Self { amount: amount.into(), address: recipient.into() }
    }

    fn amount(&self) -> MoneroAmount {
        self.amount
    }

    fn recipient(&self) -> Address {
        self.address
    }
}

impl MultisigTransaction for TestWallet {
    type Context = WritableString;
    type Preprocess = WritableString;
    type PartialSignature = SchnorrSignature<Ed25519>;
    type Transaction = WritableString;
    type PaymentType = MockPayment;

    async fn prepare_transaction<R: Send + Sync + RngCore + CryptoRng>(
        &mut self,
        payments: &[Self::PaymentType],
        ctx: &Self::Context,
        _: &mut R,
    ) -> Result<(), MultisigTxError> {
        Ok(())
    }

    fn partial_sign(
        &mut self,
        preparatory_data: &Self::Preprocess,
        ctx: &Self::Context,
    ) -> Result<(), MultisigTxError> {
        Ok(())
    }

    fn sign(
        &mut self,
        peer: Self::PartialSignature,
        ctx: &Self::Context,
    ) -> Result<Self::Transaction, MultisigTxError> {
        Ok(WritableString::new(format!("Transaction-{}", ctx.as_str())))
    }
}

#[test]
fn multisig_wallet_key_roles() {
    let mut rng = rand_core::OsRng;
    let mut merchant = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let mut customer = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);

    assert_eq!(merchant.role(), ChannelRole::Merchant);
    assert_eq!(customer.role(), ChannelRole::Customer);

    // ---> Merchant commits to public key and sends over the wire
    let commitment = merchant.commit_to_public_key();
    let data = commitment.serialize();

    // ---> Customer receives commitment, then sends back public key
    customer.set_peer_public_key_commitment(PublicKeyCommitment::read(&mut &data[..]).expect("to read commitment"));
    let data = customer.shared_public_key().serialize();

    // ---> Merchant reads in public key and returns his own public key
    merchant.set_peer_public_key(SharedPublicKey::read(&mut &data[..]).expect("to read shared public key"));
    let data = merchant.shared_public_key().serialize();

    // ---> Customer reads in and verifies the public key
    customer.set_peer_public_key(SharedPublicKey::read(&mut &data[..]).expect("to read shared public key"));
    assert!(customer.verify_peer_public_key().is_ok());
}

#[test]
fn incompatible_roles() {
    let mut rng = rand_core::OsRng;
    let m1 = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let mut m2 = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);

    m2.set_peer_public_key_commitment(m1.commit_to_public_key());
    m2.set_peer_public_key(m1.shared_public_key());
    assert!(matches!(
        m2.verify_peer_public_key(),
        Err(MultisigWalletError::IncompatibleRoles)
    ));
}

#[test]
fn invalid_commitment() {
    let mut rng = rand_core::OsRng;
    let merchant = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Merchant);
    let mut customer = MultisigWalletKeyRing::random(&mut rng, ChannelRole::Customer);
    let bad_data = [42u8; 32];
    let bad_commitment = PublicKeyCommitment::read(&mut &bad_data[..]).unwrap();
    customer.set_peer_public_key_commitment(bad_commitment);
    customer.set_peer_public_key(merchant.shared_public_key());
    assert!(matches!(
        customer.verify_peer_public_key(),
        Err(MultisigWalletError::IncorrectPublicKey)
    ));
}
