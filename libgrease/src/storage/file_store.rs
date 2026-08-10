use crate::channel_id::ChannelId;
use crate::state_machine::lifecycle::{ChannelState, LifeCycle};
use crate::storage::traits::StateStore;
use ron::ser::PrettyConfig;
use std::fs;
use std::path::{Path, PathBuf};

/// A file-based store for payment channel state.
///
/// Each channel lives in a single file named after its *stable* storage key: the provisional channel id,
/// e.g. `XGT4a7024e7….ron`. The provisional id hashes every negotiated field and no funding tag, so it is
/// fixed from the proposal onward — when [`finalize`](crate::channel_id::ChannelIdMetadata::finalize) flips
/// the channel's current id to `XGC…`, the finalized state overwrites the file its provisional state lived
/// in rather than starting a new one under the new name. No rename ever happens, so no orphaned
/// pre-finalization snapshot survives to resolve later (K-20 finding F8). The current, arbiter-facing id is
/// a property of the stored state, not of the filename.
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

    /// The path a channel's single state file lives at, keyed by the invariant provisional id.
    fn file_for(&self, key: &ChannelId) -> PathBuf {
        self.path.join(format!("{key}.ron"))
    }

    /// Resolve a final (`XGC…`) id by scanning the store for the state whose *current* name matches.
    ///
    /// Finalizing recomputes the id's hash over a transcript that absorbs the funding linking tags, so a final
    /// id does not reveal the provisional key its record is filed under and cannot be turned into a filename.
    /// Files that fail to parse are skipped — they cannot be the requested channel — with a warning.
    fn find_by_current_id(&self, channel_id: &ChannelId) -> Result<ChannelState, anyhow::Error> {
        fs::read_dir(&self.path)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "ron"))
            .filter_map(|p| {
                read_state(&p).inspect_err(|e| log::warn!("Skipping unparseable state file {}: {e}", p.display())).ok()
            })
            .find(|state| state.name() == *channel_id)
            .ok_or_else(|| anyhow::anyhow!("no channel with id {channel_id} in the store"))
    }
}

/// Read and deserialize one channel state file.
fn read_state(path: &Path) -> Result<ChannelState, anyhow::Error> {
    let val = fs::read_to_string(path)?;
    Ok(ron::de::from_str(&val)?)
}

impl StateStore for FileStore {
    /// Save `state` under its stable storage key, the provisional channel id.
    ///
    /// The key is derived from the state's own metadata, so a state written after finalization lands in the
    /// same file its provisional predecessor occupied — overwritten in place, never renamed, never orphaned.
    fn write_channel(&mut self, state: &ChannelState) -> Result<(), anyhow::Error> {
        let file_path = self.file_for(&state.metadata().channel_id().provisional_name());
        let config = PrettyConfig::new().compact_arrays(true).compact_maps(true);
        let val = ron::ser::to_string_pretty(&state, config)?;
        fs::write(&file_path, &val)?;
        Ok(())
    }

    /// Resolve `channel_id` — provisional or final — to the channel's single current state.
    ///
    /// A provisional (`XGT…`) id *is* the storage key, so it is read directly; if the channel has since
    /// finalized this returns the finalized state (whose `name()` is the `XGC…` id), because that state
    /// overwrote the provisional snapshot in place. A final id is resolved by matching each stored state's
    /// current name. Either way the result is the current state — a stale pre-finalization snapshot no
    /// longer exists to be returned.
    fn load_channel(&self, channel_id: &ChannelId) -> Result<ChannelState, anyhow::Error> {
        match channel_id.is_finalized() {
            false => read_state(&self.file_for(channel_id)),
            true => self.find_by_current_id(channel_id),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cryptography::encryption_context::{with_encryption_context, AesGcmEncryption};
    use crate::state_machine::error::LifeCycleError;
    use crate::state_machine::lifecycle::LifecycleStage;
    use crate::state_machine::{CustomerEstablishing, EstablishingState, MerchantEstablishing};
    use crate::tests::establish_channel_tests::{
        declare_funding_outputs, establish_wallet, finalize_channel_ids, fund_both, test_params,
    };
    use crate::tests::propose_channel_tests::propose_channel;
    use rand_core::OsRng;
    use std::sync::Arc;

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

    /// The names of the `.ron` files currently in the store directory, sorted.
    fn ron_files(dir: &Path) -> Vec<String> {
        let mut files: Vec<String> = std::fs::read_dir(dir)
            .expect("read store dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".ron"))
            .collect();
        files.sort();
        files
    }

    /// Re-derive the signing share from the wallet's spend key after deserialization.
    ///
    /// The signing share is `#[serde(skip)]` on [`MultisigWallet`] so it is lost during
    /// persistence. In production this would come from a fresh `prepare()` + `partial_sign()`
    /// flow; here we re-derive it from the spend key as the test helpers do.
    fn re_inject_signing_share(state: &mut EstablishingState) {
        if let Some(wallet) = state.multisig_wallet.as_mut() {
            let share = *wallet.my_spend_key().to_dalek_scalar();
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
                let (merchant_state, customer_state) = propose_channel();

                // Round-trip: both parties after proposal (no wallet yet)
                let merchant_state = round_trip(&mut store, merchant_state);
                let customer_state = round_trip(&mut store, customer_state);

                // ---- Step 2: Wrap and establish wallet ----
                let mut merchant = MerchantEstablishing::new(merchant_state, URL).expect("merchant");
                let mut customer = CustomerEstablishing::new(customer_state, URL).expect("customer");
                merchant.state_mut().set_binding_proof_params(test_params());
                customer.state_mut().set_binding_proof_params(test_params());
                establish_wallet(&mut merchant, &mut customer);
                // The customer declares the output it funds the channel with, before either side is reloaded:
                // the declaration has to survive the round trip or the linking tags cannot be derived after it.
                declare_funding_outputs(&mut merchant, &mut customer);

                // Round-trip: both parties after wallet setup
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 3: Set funding_tx_pipe ----
                merchant.state_mut().save_funding_tx_pipe(vec![]);
                customer.state_mut().save_funding_tx_pipe(vec![]);

                // Round-trip: both parties after pipe setup
                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 4: Bind the channel id to the funding outputs ----
                // The channel id changes here. The storage key does not: state is filed under the invariant
                // provisional id, so the finalized writes below overwrite the provisional snapshot in place.
                let provisional_id = merchant.state().name();
                assert!(!provisional_id.is_finalized());
                finalize_channel_ids(&mut merchant, &mut customer);

                let mut merchant = reload_merchant(&mut store, merchant);
                let mut customer = reload_customer(&mut store, customer);

                // K-20 finding F8: a lookup by the provisional id must resolve the *current* (finalized)
                // state, not a stale pre-finalization snapshot, and no second file may be left behind.
                // (Both parties share the channel id, and so — in this shared test directory — one file.)
                let final_id = merchant.state().name();
                assert!(final_id.is_finalized());
                assert_ne!(provisional_id, final_id);
                let by_provisional = store.load_channel(&provisional_id).expect("provisional id resolves");
                assert_eq!(
                    by_provisional.as_lifecycle().name(),
                    final_id,
                    "a provisional lookup must resolve the finalized state, not resurrect the provisional one"
                );
                let by_final = store.load_channel(&final_id).expect("final id resolves the same record");
                assert_eq!(by_final.as_lifecycle().name(), final_id);
                assert_eq!(
                    ron_files(&dir),
                    vec![format!("{provisional_id}.ron")],
                    "finalization must not orphan the provisional state file"
                );

                // ---- Step 5: Customer generates its initial-state package ----
                // Signing shares were re-injected by reload_*
                let customer_pkg = customer.generate_init_package(&mut rng).expect("customer init package");

                // Round-trip: the customer holds its offset and its own package
                let customer = reload_customer(&mut store, customer);

                // ---- Step 6: Merchant verifies and accepts it ----
                merchant.receive_customer_init_package(customer_pkg).expect("merchant receives customer package");

                // Round-trip: merchant has peer data. Re-inject signing share because
                // merchant still needs to generate their own init package.
                let mut merchant = reload_merchant(&mut store, merchant);

                // ---- Step 7: Merchant generates its initial-state package ----
                let merchant_pkg = merchant.generate_init_package(&mut rng).expect("merchant init package");

                // Round-trip: the merchant holds its offset and both packages
                let mut merchant = reload_merchant(&mut store, merchant);

                // ---- Step 8: Customer verifies and accepts it ----
                let mut customer = reload_customer(&mut store, customer);
                customer.receive_merchant_init_package(merchant_pkg).expect("customer receives merchant package");

                // Round-trip: customer has peer data
                let mut customer = reload_customer(&mut store, customer);

                // ---- Step 9: Fund the channel ----
                fund_both(&mut merchant, &mut customer);

                // Round-trip: both have funding tx
                let merchant = reload_merchant(&mut store, merchant);
                let customer = reload_customer(&mut store, customer);

                // ---- Step 10: Verify requirements and transition to Established ----
                assert!(merchant.state().requirements_met(), "merchant requirements not met");
                assert!(customer.state().requirements_met(), "customer requirements not met");

                let established_m = merchant.into_inner().next().map_err(|(s, e)| (s.to_channel_state(), e))?;
                let established_c = customer.into_inner().next().map_err(|(s, e)| (s.to_channel_state(), e))?;

                // ---- Step 11: Round-trip the Established state ----
                let cs_m = established_m.to_channel_state();
                let id = cs_m.as_lifecycle().name();
                store.write_channel(&cs_m).expect("write established merchant");
                let loaded_m = store.load_channel(&id).expect("load established merchant");
                assert_eq!(loaded_m.as_lifecycle().stage(), LifecycleStage::Open);
                // The state-0 record was assembled from two halves that had themselves been through the store,
                // and it survives the open channel's own round trip.
                let open_m = loaded_m.to_open().map_err(|(_, e)| e).expect("an open channel");
                assert_eq!(
                    open_m.current_record().map(|r| r.update_count()),
                    Some(0),
                    "an opened channel must carry its state-0 record"
                );

                let cs_c = established_c.to_channel_state();
                store.write_channel(&cs_c).expect("write established customer");
                let loaded_c = store.load_channel(&id).expect("load established customer");
                assert_eq!(loaded_c.as_lifecycle().stage(), LifecycleStage::Open);

                // The whole lifecycle lived in the one file keyed by the provisional id.
                assert_eq!(ron_files(&dir), vec![format!("{provisional_id}.ron")]);

                let _ = std::fs::remove_dir_all(&dir);
                Ok(())
            }
            let _ = inner().map_err(|(_s, e)| panic!("{e}"));
        });
    }

    /// Both lookup paths must miss cleanly for a channel the store has never seen: the provisional form
    /// reads its key's file directly, the final form scans for a matching current name.
    #[test]
    fn unknown_ids_do_not_resolve() {
        use std::str::FromStr;

        let dir = std::env::temp_dir().join(format!("grease_file_store_miss_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = FileStore::new(dir.clone()).expect("create file store");

        let hex = "4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let provisional = ChannelId::from_str(&format!("XGT{hex}")).unwrap();
        let final_id = ChannelId::from_str(&format!("XGC{hex}")).unwrap();
        assert!(store.load_channel(&provisional).is_err(), "an unknown provisional id must not resolve");
        assert!(store.load_channel(&final_id).is_err(), "an unknown final id must not resolve");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
