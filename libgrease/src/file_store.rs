use crate::crypto::traits::PublicKey;
use crate::kes::KeyEscrowService;
use crate::monero::MultiSigWallet;
use crate::payment_channel::ActivePaymentChannel;
use crate::state_machine::traits::StateStore;
use crate::state_machine::ChannelLifeCycle;
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

impl<P, C, W, KES> StateStore<P, C, W, KES> for FileStore
where
    P: PublicKey,
    C: ActivePaymentChannel,
    W: MultiSigWallet,
    KES: KeyEscrowService,
{
    fn write_channel(&mut self, state: &ChannelLifeCycle<P, C, W, KES>) -> Result<(), anyhow::Error> {
        let file_path = self.path.join(format!("{}.ron", state.current_state().name()));
        let config = PrettyConfig::new().compact_arrays(true).compact_maps(true);
        let val = ron::ser::to_string_pretty(state, config)?;
        fs::write(&file_path, &val)?;
        Ok(())
    }

    fn load_channel(&self, name: &str) -> Result<ChannelLifeCycle<P, C, W, KES>, anyhow::Error> {
        let file_path = self.path.join(format!("{}.ron", name));
        let val = fs::read_to_string(&file_path)?;
        let channel: ChannelLifeCycle<P, C, W, KES> = ron::de::from_str(&val)?;
        Ok(channel)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::payment_channel::ClosedPaymentChannel;
    use crate::state_machine::lifecycle::test::*;

    /// Saves and loads the state after every transition. We should be able to carry on as if nothing happened.
    #[tokio::test]
    async fn test_file_store() {
        let path = PathBuf::from("./test_data");
        let mut store = FileStore::new(path).expect("directory to exist");
        let (mut lc, initial_state) = new_channel_state();
        let name = initial_state.channel_info.channel_id.name();
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");
        lc = accept_proposal(lc, &initial_state).await;
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");

        lc = create_wallet(lc).await;
        lc = verify_kes(lc).await;
        lc = open_channel(lc).await;
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");

        lc = payment(lc, MoneroAmount::from_xmr("0.1").unwrap()).await;
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");

        lc = start_close(lc).await;
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");

        lc = successful_close(lc).await;
        store.write_channel(&lc).expect("Failed to write channel");
        lc = store.load_channel(&name).expect("Failed to load channel");
        let final_balance = lc.closed_channel().unwrap().final_balance();
        assert_eq!(final_balance.customer, MoneroAmount::from_xmr("1.15").unwrap());
    }
}
