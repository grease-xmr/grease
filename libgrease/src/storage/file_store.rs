use crate::channel_id::ChannelId;
use crate::state_machine::lifecycle::{ChannelState, LifeCycle};
use crate::storage::traits::StateStore;
use ron::ser::PrettyConfig;
use std::fs;
use std::path::PathBuf;

/// A file-based store for payment channel state.
///
/// Each channel is saved in a file with the channel ID as the filename, e.g. `XGCa2edd1f8091cc375b12357b427a748ba.ron`
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Creates a new file store with the given path.
    ///
    /// # Arguments
    /// * `path` - The path to the directory where the channel files will be stored.
    pub fn new(path: PathBuf) -> Result<Self, std::io::Error> {
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        Ok(Self { path })
    }

    /// Returns the path to the directory where the channel files are stored.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl StateStore for FileStore {
    fn write_channel(&mut self, state: &ChannelState) -> Result<(), anyhow::Error> {
        let file_path = self.path.join(format!("{}.ron", state.name()));
        let config = PrettyConfig::new().compact_arrays(true).compact_maps(true);
        let val = ron::ser::to_string_pretty(&state, config)?;
        fs::write(&file_path, &val)?;
        Ok(())
    }

    fn load_channel(&self, channel_id: &ChannelId) -> Result<ChannelState, anyhow::Error> {
        let file_path = self.path.join(format!("{channel_id}.ron"));
        let val = fs::read_to_string(&file_path)?;
        let state: ChannelState = ron::de::from_str(&val)?;
        Ok(state)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption};
    use crate::grease_protocol::kes_establishing::KesEstablishing;
    use crate::state_machine::error::LifeCycleError;
    use crate::state_machine::lifecycle::LifecycleStage;
    use crate::state_machine::{CustomerEstablishing, EstablishingState, MerchantEstablishing};
    use crate::tests::establish_channel_tests::{establish_wallet, fake_tx, fund_both, inject_signing_shares};
    use crate::tests::propose_channel_tests::propose_channel;
    use crate::XmrScalar;
    use rand_core::OsRng;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const URL: &str = "No RPC required";

    /// Save an [`EstablishingState`] to the store and load it back.
    fn round_trip(store: &mut FileStore, state: EstablishingState) -> EstablishingState {
        let cs = state.to_channel_state();
        let id = cs.as_lifecycle().name();
        store.write_channel(&cs).expect("write_channel");
        store.load_channel(&id).expect("load_channel").to_establishing().map_err(|(_, e)| e).expect("to_establishing")
    }

    /// Save, load, and re-wrap a merchant. Re-injects the signing share since it is
    /// transient (`#[serde(skip)]`) and must be re-derived after deserialization.
    fn reload_merchant(store: &mut FileStore, m: MerchantEstablishing) -> MerchantEstablishing {
        let mut state = round_trip(store, m.into_inner());
        re_inject_signing_share(&mut state);
        MerchantEstablishing::new(state, URL).expect("re-wrap merchant")
    }

    /// Save, load, and re-wrap a customer. Re-injects the signing share.
    fn reload_customer(store: &mut FileStore, c: CustomerEstablishing) -> CustomerEstablishing {
        let mut state = round_trip(store, c.into_inner());
        re_inject_signing_share(&mut state);
        CustomerEstablishing::new(state, URL).expect("re-wrap customer")
    }

    /// Re-derive the signing share from the wallet's spend key after deserialization.
    ///
    /// The signing share is `#[serde(skip)]` on [`MultisigWallet`] so it is lost during
    /// persistence. In production this would come from a fresh `prepare()` + `partial_sign()`
    /// flow; here we re-derive it from the spend key as the test helpers do.
    fn re_inject_signing_share(state: &mut EstablishingState) {
        if let Some(wallet) = state.multisig_wallet.as_mut() {
            let share = XmrScalar(*wallet.my_spend_key().to_dalek_scalar());
            wallet.inject_test_signing_share(&share);
        }
    }

    /// Saves and loads the state after every step of the establishment protocol.
    /// Each party's state should survive a full serialization round-trip and
    /// continue as if nothing happened.
    #[test]
    fn test_file_store() {
        let ctx = Arc::new(AesGcmEncryption::random());
        with_encryption_context(ctx, || {
            fn inner() -> Result<(), (ChannelState, LifeCycleError)> {
                let dir = std::env::temp_dir().join(format!("grease_file_store_test_{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                let mut store = FileStore::new(dir.clone()).expect("create file store");
                let mut rng = OsRng;

                // ---- Step 1: Channel proposal exchange ----
                let (merchant_state, customer_state, kes_key) = propose_channel();

                // Round-trip: both parties after proposal (no wallet yet)
                let merchant_state = round_trip(&mut store, merchant_state);
                let customer_state = round_trip(&mut store, customer_state);

                // ---- Step 2: Wrap and establish wallet ----
                let mut merchant = MerchantEstablishing::new(merchant_state, URL).expect("merchant");
                let mut customer = CustomerEstablishing::new(customer_state, URL).expect("customer");
                establish_wallet(&mut merchant, &mut customer);

                // Round-trip: both parties after wallet setup
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 3: Set funding_tx_pipe ----
                merchant.state_mut().save_funding_tx_pipe(vec![]);
                customer.state_mut().save_funding_tx_pipe(vec![]);

                // Round-trip: both parties after pipe setup
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 4: Customer generates init package ----
                // Signing shares were re-injected by reload_*
                let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");

                // Round-trip: customer has adapted_sig + payload_sig stored
                let customer = reload_customer(&mut store, customer);

                // ---- Step 5: Merchant receives customer init package ----
                merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

                // Round-trip: merchant has peer data. Re-inject signing share because
                // merchant still needs to generate their own init package.
                let mut merchant = reload_merchant(&mut store, merchant);

                // ---- Step 6: Merchant generates init package ----
                let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");

                // Round-trip: merchant has adapted_sig + payload_sig stored
                let merchant = reload_merchant(&mut store, merchant);

                // ---- Step 7: Customer receives merchant init package ----
                let mut customer = reload_customer(&mut store, customer);
                customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");

                // Round-trip: customer has peer data
                let customer = reload_customer(&mut store, customer);

                // ---- Step 8: KES bundle + validation ----
                let kes_bundle = merchant.bundle_for_kes(&mut rng).expect("bundle for KES");
                let kes_secret = Zeroizing::new(kes_key);
                let kes = KesEstablishing::from_bundle(kes_secret, kes_bundle).expect("KES from bundle");
                let (proofs, record) = kes.finalize(&mut rng);
                assert_eq!(record.channel_id, merchant.state().metadata.channel_id().name());

                // ---- Step 9: Receive KES proofs ----
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);
                merchant.receive_kes_proof(proofs.clone()).expect("merchant KES proofs");
                customer.receive_kes_proof(proofs).expect("customer KES proofs");

                // Round-trip: both have KES proof
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 10: Fund the channel ----
                fund_both(&mut merchant, &mut customer);

                // Round-trip: both have funding tx
                let merchant = reload_merchant(&mut store, merchant);
                let customer = reload_customer(&mut store, customer);

                // ---- Step 11: Verify requirements and transition to Established ----
                assert!(merchant.state().requirements_met(), "merchant requirements not met");
                assert!(customer.state().requirements_met(), "customer requirements not met");

                let established_m = merchant.into_inner().next().map_err(|(s, e)| (s.to_channel_state(), e))?;
                let established_c = customer.into_inner().next().map_err(|(s, e)| (s.to_channel_state(), e))?;

                // ---- Step 12: Round-trip the Established state ----
                let cs_m = established_m.to_channel_state();
                let id = cs_m.as_lifecycle().name();
                store.write_channel(&cs_m).expect("write established merchant");
                let loaded_m = store.load_channel(&id).expect("load established merchant");
                assert_eq!(loaded_m.as_lifecycle().stage(), LifecycleStage::Open);

                let cs_c = established_c.to_channel_state();
                store.write_channel(&cs_c).expect("write established customer");
                let loaded_c = store.load_channel(&id).expect("load established customer");
                assert_eq!(loaded_c.as_lifecycle().stage(), LifecycleStage::Open);

                let _ = std::fs::remove_dir_all(&dir);
                Ok(())
            }
            let _ = inner().map_err(|(_s, e)| panic!("{e}"));
        });
    }
}
