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

    fn load_channel(&self, name: &str) -> Result<ChannelState, anyhow::Error> {
        let file_path = self.path.join(format!("{}.ron", name));
        let val = fs::read_to_string(&file_path)?;
        let state: ChannelState = ron::de::from_str(&val)?;
        Ok(state)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::monero::data_objects::TransactionId;
    use crate::state_machine::error::LifeCycleError;
    use crate::state_machine::lifecycle::test::*;
    use crate::state_machine::{ChannelCloseRecord, ChannelClosedReason};

    /// Saves and loads the state after every transition. We should be able to carry on as if nothing happened.
    #[test]
    fn test_file_store() {
        fn inner() -> Result<(), (ChannelState, LifeCycleError)> {
            let path = PathBuf::from("./test_data");
            let mut store = FileStore::new(path).expect("directory to exist");
            let state = new_channel_state(&mut rand::rng()).to_channel_state();
            let name = state.name();
            store.write_channel(&state).expect("Failed to write channel");
            let _loaded = store.load_channel(&name).expect("Failed to load New channel");
            let new = state.to_new()?;
            let establishing = accept_proposal(new).to_channel_state();
            store.write_channel(&establishing).expect("Failed to write channel");
            let state = store.load_channel(&name).expect("Failed to load Establishing channel");
            let establishing = state.to_establishing()?;
            let open = establish_channel(establishing).to_channel_state();
            store.write_channel(&open).expect("Failed to write channel");
            let loaded = store.load_channel(&name).expect("Failed to load Open channel");
            let mut open = loaded.to_open()?;
            payment(&mut open, "0.1");
            let state = open.to_channel_state();
            store.write_channel(&state).expect("Failed to write channel");
            let state = store.load_channel(&name).expect("Failed to load Open channel").to_open()?;
            assert_eq!(state.update_count(), 1);
            assert_eq!(state.my_balance(), MoneroAmount::from_xmr("1.15").unwrap());
            let close = ChannelCloseRecord {
                final_balance: state.balance(),
                update_count: state.update_count(),
                witness: Default::default(),
            };
            let state = state.close(close).unwrap().to_channel_state();
            store.write_channel(&state).expect("Failed to write channel");
            let loaded = store.load_channel(&name).expect("Failed to load Closing channel");
            let mut state = loaded.to_closing()?;
            assert_eq!(state.reason, ChannelClosedReason::Normal);
            state.with_final_tx(TransactionId::new("finaltx1"));
            let state = state.next().expect("Failed to close channel").to_channel_state();
            store.write_channel(&state).expect("Failed to write channel");
            let loaded = store.load_channel(&name).expect("Failed to load Open channel");
            let state = loaded.to_closed()?;
            assert_eq!(state.balance().customer, MoneroAmount::from_xmr("1.15").unwrap());
            Ok(())
        }
        let _ = inner().map_err(|(_s, e)| panic!("{}", e));
    }
}
