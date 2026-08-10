use crate::channel_id::ChannelId;
use crate::state_machine::lifecycle::ChannelState;

/// Persistence for channel state, keyed by the channel's *stable* id.
///
/// A channel's current [`ChannelId`] changes exactly once in its life:
/// [`finalize`](crate::channel_id::ChannelIdMetadata::finalize) binds it to the funding output, replacing the
/// provisional `XGT…` id with the final `XGC…` one. A store must therefore never key a record by the current
/// id — the record would be orphaned under the old name at that moment (K-20 finding F8). Implementations key
/// by the invariant provisional id ([`provisional_name`](crate::channel_id::ChannelIdMetadata::provisional_name))
/// and treat the current, arbiter-facing id as data *inside* the state:
///
/// - [`write_channel`](Self::write_channel) derives the key from the state itself, so writing a finalized
///   state overwrites the record its provisional state lived in. Nothing is renamed, so nothing is orphaned.
/// - [`load_channel`](Self::load_channel) resolves *either* form of the id to the single current state. In
///   particular, a lookup by provisional id after finalization returns the finalized state — whose `name()`
///   is the `XGC…` id — never a stale pre-finalization snapshot.
pub trait StateStore {
    fn write_channel(&mut self, state: &ChannelState) -> Result<(), anyhow::Error>;
    fn load_channel(&self, channel_id: &ChannelId) -> Result<ChannelState, anyhow::Error>;
}
