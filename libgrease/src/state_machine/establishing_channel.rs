//! The `Establishing` lifecycle state.
//!
//! Spec: `docs/src/14_establishing_channel.typ` §`initProtocol`, with the message flow in
//! `docs/diagrams/establish_channel_sequence_a.md` and `..._b.md`.
//!
//! Establishment runs in six moves, and the arbiter plays no part in any of them:
//!
//! 1. **Shared wallet.** The two parties run the commit-then-reveal key exchange in
//!    [`multisig_setup`](crate::state_machine::multisig_setup) and end up holding the same 2-of-2 FROST wallet.
//! 2. **Funding declaration.** Each funding party names the transaction public key `R_j` and output index
//!    `i_j` of the output it will contribute. Both parties then derive that output's one-time key `K_j` and
//!    derivation scalar `d_j` themselves, from the shared view key — nothing but `(R_j, i_j)` is taken from the
//!    counterparty's message.
//! 3. **Final channel id.** For each declared output the parties jointly derive its linking tag
//!    `L_j = (d_j + x)·H_p(K_j)`, the key image its spend will publish — each contributes a partial tag from
//!    its own offset MuSig share, with a proof that it did so honestly — and bind the channel id to the set.
//!    The provisional `XGT…` id from the proposal becomes the final `XGC…` id, and every signature exchanged
//!    afterwards commits to it.
//! 4. **Initial commitment transaction.** The FROST preprocessing round trip, after which each side can adapt
//!    its partial signature.
//! 5. **Initial state exchange.** Each party draws a fresh offset `ω`, adapter-signs the *counterparty's*
//!    closing transaction with it, seals `ω` to the statement `m = (channel_id, 0)` under the arbiter's master
//!    key, and sends the resulting [`ChannelInitPackage`]. Each verifies the counterparty's binding proof and
//!    adaptor signature before accepting the initial state.
//! 6. **Funding.** Only now do the funding parties broadcast, each holding everything the counterparty owes it
//!    ([`ready_to_fund`](EstablishingState::ready_to_fund)); once the funding transactions confirm, both sides
//!    move to `Open`.

use crate::amount::MoneroAmount;
use crate::balance::Balances;
use crate::channel_id::{ChannelId, ChannelIdMetadata};
use crate::channel_metadata::{DynamicChannelMetadata, StaticChannelMetadata};
use crate::cryptography::binding_proof::BindingProofParams;
use crate::cryptography::keys::{Curve25519PublicKey, Curve25519Secret, PublicKey, PublicKeyCommitment};
use crate::cryptography::linking_tag::PartialLinkingTag;
use crate::cryptography::serializable_secret::SerializableSecret;
use crate::grease_protocol::establish_channel::{ChannelInitPackage, EstablishError, INITIAL_UPDATE_COUNT};
use crate::grease_protocol::multisig_wallet::{LinkedMultisigWallets, MultisigWalletError, SharedPublicKey};
use crate::grease_protocol::update_record::{CloseHash, HalfSignedUpdateRecord, UpdateRecord};
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::payment_channel::multisig_negotiation::MultisigWalletKeyNegotiation;
use crate::payment_channel::{ChannelRole, HasRole};
use crate::state_machine::error::LifeCycleError;
use crate::state_machine::lifecycle::ChannelState;
use crate::state_machine::open_channel::{AppliedUpdate, EstablishedChannelState, UpdateHistory};
use crate::state_machine::proposing_channel::{AwaitingConfirmation, AwaitingProposalResponse};
use crate::wallet::multisig_wallet::{
    commitment_pair_message, commitment_tx_message, DerivedFundingOutput, FundingOutputRef,
};
use crate::Ed25519;
use crate::XmrScalar;
use ciphersuite::group::GroupEncoding;
use ciphersuite::Ciphersuite;
use log::*;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

//------------------------------------   Establishing Channel State  ------------------------------------------------//

/// State for a channel being established.
///
/// It carries the material the two parties build during establishment: the shared wallet, the final channel id,
/// this party's fresh initial offset `ω` and the two [`ChannelInitPackage`]s that fix the initial state.
///
/// The generic parameter `KC` is the curve the channel keys live on. It is `Ed25519` — the same curve as Monero —
/// everywhere in practice, and the protocol steps that touch Monero material are implemented for that curve only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = "KC::F: ciphersuite::group::ff::PrimeFieldBits"))]
pub struct EstablishingState<KC = Ed25519>
where
    KC: Ciphersuite,
{
    // Variables specified at start of stage
    pub(crate) metadata: StaticChannelMetadata<KC>,
    /// This party's channel key, `k_a` (customer) or `k_b` (merchant). Its public key is the party's key in the
    /// channel-id transcript, and that is all it is: the channel id is derived from it during negotiation and
    /// nothing afterwards signs with it. Every [`UpdateRecord`] half — state 0's included — is signed with the
    /// *wallet spend key*, because that is the key the arbiter registers and the dispute path verifies against.
    ///
    /// [`UpdateRecord`]: crate::grease_protocol::update_record::UpdateRecord
    pub(crate) channel_secret: SerializableSecret<KC::F>,
    /// This party's half of the multisig wallet's private spend key.
    pub(crate) wallet_partial_spend_key: Curve25519Secret,

    // Variables determined during the stage
    pub(crate) multisig_wallet: Option<MultisigWallet>,
    #[serde(
        serialize_with = "crate::helpers::serialize_tx_map",
        deserialize_with = "crate::helpers::deserialize_tx_map"
    )]
    pub(crate) funding_transaction_ids: HashMap<TransactionId, TransactionRecord>,
    /// Data used to watch for the funding transaction. Implementation agnostic.
    #[serde(
        serialize_with = "crate::helpers::option_to_hex",
        deserialize_with = "crate::helpers::option_from_hex",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub(crate) funding_tx_pipe: Option<Vec<u8>>,
    /// The cut-and-choose profile this channel's binding proofs use. Production unless a test lowers it.
    #[serde(default = "BindingProofParams::production")]
    pub(crate) binding_proof_params: BindingProofParams,
    /// Our fresh secret offset `ω_0` for the initial state, kept until that state is superseded or the channel
    /// closes cooperatively. Encrypted at rest.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) initial_offset: Option<SerializableSecret<XmrScalar>>,
    /// The package we sent the counterparty.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) my_init_package: Option<ChannelInitPackage>,
    /// The counterparty's package, stored only after it verified in full.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_init_package: Option<ChannelInitPackage>,
    /// This party's funding-output declaration, present once it has declared. `None` for a party that
    /// committed no initial balance and therefore funds nothing.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) my_funding_output: Option<FundingOutputRef>,
    /// The counterparty's funding-output declaration, as received.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub(crate) peer_funding_output: Option<FundingOutputRef>,
    #[serde(skip)]
    pub(crate) preprepare_data: Vec<u8>,
}

/// Type alias for the default channel curve (Ed25519).
pub type DefaultEstablishingState = EstablishingState;

impl<KC> EstablishingState<KC>
where
    KC: Ciphersuite,
{
    //---------------------------------------  Constructors -------------------------------------------------------//

    fn new(
        metadata: StaticChannelMetadata<KC>,
        channel_secret: SerializableSecret<KC::F>,
        wallet_partial_spend_key: Curve25519Secret,
    ) -> Self {
        Self {
            metadata,
            channel_secret,
            wallet_partial_spend_key,
            multisig_wallet: None,
            funding_transaction_ids: Default::default(),
            funding_tx_pipe: None,
            binding_proof_params: BindingProofParams::production(),
            initial_offset: None,
            my_init_package: None,
            peer_init_package: None,
            my_funding_output: None,
            peer_funding_output: None,
            preprepare_data: vec![],
        }
    }

    //---------------------------------------  Accessors -------------------------------------------------------//

    /// Provide access to the channel ID metadata.
    pub fn channel_id_metadata(&self) -> &ChannelIdMetadata<KC> {
        self.metadata.channel_id()
    }

    /// The channel id as it stands: provisional (`XGT…`) until the funding output's linking tag is bound to it.
    pub fn channel_id(&self) -> ChannelId {
        self.metadata.channel_id().name()
    }

    /// The partial wallet public key
    pub fn partial_wallet_public_key(&self) -> Curve25519PublicKey {
        Curve25519PublicKey::from_secret(&self.wallet_partial_spend_key)
    }

    /// The package this party sent, if it has been generated.
    pub fn my_init_package(&self) -> Option<&ChannelInitPackage> {
        self.my_init_package.as_ref()
    }

    /// The counterparty's package, present only once it verified in full.
    pub fn peer_init_package(&self) -> Option<&ChannelInitPackage> {
        self.peer_init_package.as_ref()
    }

    /// The cross-signed record for state 0, assembled from the two halves the packages carry. Present exactly
    /// once both packages have been exchanged and verified.
    ///
    /// [`UpdateRecord::from_halves`] is order-independent and byte-identical on both sides, so the two parties
    /// end up holding the same record rather than two records that merely agree on their fields.
    pub fn initial_record(&self) -> Result<UpdateRecord, EstablishError> {
        let mine = self.require_package(&self.my_init_package, "Our initial-state package")?;
        let peer = self.require_package(&self.peer_init_package, "The counterparty's initial-state package")?;
        let record = UpdateRecord::from_halves(&mine.record_half, &peer.record_half)?;
        Ok(record)
    }

    /// Whether this party may broadcast its funding transaction.
    ///
    /// True only once the counterparty's package has been accepted: before that we hold no exit we could
    /// complete and no record we could present, so a deposit broadcast now could be stranded by a counterparty
    /// that simply stops answering. This is the gate `docs/src/14_establishing_channel.typ` §preSigning step 5
    /// describes; funding itself arrives from outside the state machine, so this is the surface that expresses
    /// it.
    pub fn ready_to_fund(&self) -> bool {
        self.metadata.channel_id().is_finalized() && self.peer_init_package.is_some()
    }

    fn require_package<'a>(
        &self,
        slot: &'a Option<ChannelInitPackage>,
        what: &str,
    ) -> Result<&'a ChannelInitPackage, EstablishError> {
        slot.as_ref().ok_or_else(|| EstablishError::MissingInformation(what.to_string()))
    }

    pub fn multisig_address(&self) -> Option<String> {
        self.multisig_wallet.as_ref().map(|w| w.address().to_string())
    }

    pub fn funding_total(&self) -> MoneroAmount {
        self.funding_transaction_ids.values().map(|r| r.amount).sum()
    }

    pub fn multisig_wallet_data(&self) -> Option<&MultisigWallet> {
        self.multisig_wallet.as_ref()
    }

    /// The cut-and-choose profile this channel's binding proofs use.
    pub fn binding_proof_params(&self) -> BindingProofParams {
        self.binding_proof_params
    }

    /// Lower the binding-proof profile. Test-only: production soundness is not negotiable on a live channel.
    #[cfg(any(test, feature = "mocks"))]
    pub fn set_binding_proof_params(&mut self, params: BindingProofParams) {
        self.binding_proof_params = params;
    }

    //---------------------------------------  Setters -------------------------------------------------------//

    pub fn wallet_created(&mut self, wallet: MultisigWallet) {
        debug!("Multisig wallet has been created.");
        let old = self.multisig_wallet.replace(wallet);
        if old.is_some() {
            warn!("Wallet state was already set and has been replaced.");
        }
    }

    /// Can be used to save (e.g. a unix pipe or filename) that will be used to watch for the funding transaction.
    /// Once the funding tx is broadcast, call `funding_tx_confirmed` to update the state.
    pub fn save_funding_tx_pipe(&mut self, funding_tx_pipe: Vec<u8>) {
        debug!("Saving funding transaction pipe data");
        let old = self.funding_tx_pipe.replace(funding_tx_pipe);
        if old.is_some() {
            warn!("Funding transaction pipe data was already set and has been replaced.");
        }
    }

    pub fn funding_tx_confirmed(&mut self, transaction: TransactionRecord) {
        debug!("Funding transaction broadcasted");
        self.funding_transaction_ids.insert(transaction.transaction_id.clone(), transaction);
    }

    //---------------------------------------  Funding declarations  ---------------------------------------------//

    /// Whether `role` funds this channel, read off the balances it committed to during negotiation.
    ///
    /// `docs/src/14_establishing_channel.typ` §fundingDeclaration: a channel is funded by one output per
    /// funding party, and "the initial balances absorbed into the channel id transcript are exactly those
    /// contributions". A party that brings nothing to the channel contributes no output and no linking tag.
    pub fn funds_the_channel(&self, role: ChannelRole) -> bool {
        let balances = self.metadata.initial_balance();
        let contribution = match role {
            ChannelRole::Merchant => balances.merchant,
            ChannelRole::Customer => balances.customer,
        };
        !contribution.is_zero()
    }

    /// Declare the funding output *this* party will contribute.
    ///
    /// Refused if this party funds nothing, and refused a second time: a declaration determines one of the
    /// linking tags the channel id is about to be bound to, so silently replacing one would change the id under
    /// a counterparty that has already derived it.
    pub fn declare_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        let role = HasRole::role(self);
        let funds = self.funds_the_channel(role);
        Self::accept_declaration(&mut self.my_funding_output, output, role, funds)
    }

    /// Record the counterparty's funding-output declaration.
    ///
    /// Only `(R_j, i_j)` is taken from the peer; the output itself is derived locally from the shared view key
    /// ([`funding_outputs`](Self::funding_outputs)). Whether the peer is entitled to declare *this particular*
    /// output is the out-proof's job, which is not implemented yet (K-45); what is checked here is that the
    /// peer is a funding party at all, and that it declares once.
    pub fn receive_peer_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        let role = HasRole::role(self).other();
        let funds = self.funds_the_channel(role);
        Self::accept_declaration(&mut self.peer_funding_output, output, role, funds)
    }

    fn accept_declaration(
        slot: &mut Option<FundingOutputRef>,
        output: FundingOutputRef,
        role: ChannelRole,
        funds: bool,
    ) -> Result<(), EstablishError> {
        if !funds {
            return Err(EstablishError::NotAFundingParty(role));
        }
        if slot.is_some() {
            return Err(EstablishError::FundingOutputAlreadyDeclared(role));
        }
        *slot = Some(output);
        debug!("The {role} declared its funding output");
        Ok(())
    }

    /// This party's declaration, if it has made one.
    pub fn my_funding_output(&self) -> Option<&FundingOutputRef> {
        self.my_funding_output.as_ref()
    }

    /// The counterparty's declaration, if it has been received.
    pub fn peer_funding_output(&self) -> Option<&FundingOutputRef> {
        self.peer_funding_output.as_ref()
    }

    /// Whether every funding party has declared the output it will contribute.
    pub fn every_funding_output_declared(&self) -> bool {
        let me = HasRole::role(self);
        let declared = |funds: bool, slot: &Option<FundingOutputRef>| !funds || slot.is_some();
        declared(self.funds_the_channel(me), &self.my_funding_output)
            && declared(self.funds_the_channel(me.other()), &self.peer_funding_output)
    }

    /// The declarations that make up the channel's funding set, in role order (ours first).
    ///
    /// Used only as the input to the local derivation; the canonical ordering the two parties agree on is by
    /// one-time key, applied in [`funding_outputs`](Self::funding_outputs).
    fn declarations(&self) -> Result<Vec<FundingOutputRef>, EstablishError> {
        if !self.every_funding_output_declared() {
            return Err(EstablishError::MissingInformation(
                "A funding output declaration — every funding party must declare before the id can be bound".into(),
            ));
        }
        Ok([self.my_funding_output, self.peer_funding_output].into_iter().flatten().collect())
    }

    //-----------------------------------  Initial commitment transaction  ---------------------------------------//

    /// Prepare the initial commitment transaction for signing.
    ///
    /// This creates the transaction that pays the initial balances to the closing addresses,
    /// generates MuSig2 nonces, and stores the preprocess data for exchange with the peer.
    ///
    /// After calling this, exchange preprocess data with the peer using [`preprepare_data()`]
    /// and [`receive_peer_preprocess_data()`], then call [`generate_init_package()`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        use crate::wallet::common::MINIMUM_FEE;
        use crate::wallet::multisig_wallet::translate_payments;

        // Build payment destinations from closing addresses and initial balance
        let closing_addrs = *self.metadata.channel_id().closing_addresses();
        let balances = self.metadata.initial_balance();
        let unadjusted = [(closing_addrs.merchant, balances.merchant), (closing_addrs.customer, balances.customer)];
        let fee = MoneroAmount::from_piconero(MINIMUM_FEE);
        let payments = translate_payments(unadjusted, fee).map_err(MultisigWalletError::from)?;

        let wallet = self.require_wallet_mut()?;
        // Prepare the transaction (creates signing machine and generates nonces)
        let mut rng = wallet.deterministic_rng();
        wallet.prepare(payments, &mut rng).await.map_err(MultisigWalletError::from)?;

        // Store the preprocess data for exchange
        let pp_data = wallet
            .my_pre_process_data()
            .ok_or_else(|| EstablishError::MissingInformation("Failed to generate preprocess data".into()))?;
        self.preprepare_data = pp_data;

        Ok(())
    }

    /// Receive peer's preprocess data and complete the partial signing step.
    ///
    /// This stores the peer's preprocess data in the wallet and calls `partial_sign()`
    /// to generate our signing share. After this, [`generate_init_package()`] can be called.
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        let wallet = self.require_wallet_mut()?;
        wallet.set_peer_process_data(data);
        wallet.partial_sign().map_err(MultisigWalletError::from)?;
        Ok(())
    }

    /// Returns a copy of the initial commit transaction pre-prepare data, if it exists.
    pub fn preprepare_data(&self) -> Result<Vec<u8>, EstablishError> {
        if self.preprepare_data.is_empty() {
            Err(EstablishError::MissingInformation("Preprepare data".into()))
        } else {
            Ok(self.preprepare_data.clone())
        }
    }

    fn require_wallet(&self) -> Result<&MultisigWallet, EstablishError> {
        self.multisig_wallet
            .as_ref()
            .ok_or_else(|| EstablishError::MissingInformation("Multisig wallet not created yet".into()))
    }

    fn require_wallet_mut(&mut self) -> Result<&mut MultisigWallet, EstablishError> {
        self.multisig_wallet
            .as_mut()
            .ok_or_else(|| EstablishError::MissingInformation("Multisig wallet not created yet".into()))
    }

    //---------------------------------------  State transition ------------------------------------------------------//

    pub fn requirements_met(&self) -> bool {
        let mut missing = Vec::with_capacity(8);
        if self.multisig_wallet.is_none() {
            missing.push("Multisig wallet");
        }
        if !self.every_funding_output_declared() {
            missing.push("Every funding output declared");
        }
        if !self.metadata.channel_id().is_finalized() {
            missing.push("Final channel id (the funding outputs' linking tags have not been bound to it)");
        }
        if self.my_init_package.is_none() {
            missing.push("Our initial-state package");
        }
        if self.peer_init_package.is_none() {
            missing.push("The counterparty's initial-state package");
        }
        if self.initial_record().is_err() {
            missing.push("Cross-signed state-0 record");
        }
        if self.funding_tx_pipe.is_none() {
            error!("Funding transaction pipe data is required to detect channel funding, but it is missing.");
            missing.push("Funding transaction pipe data. We will never be able to detect if this channel is funded without this.");
        }
        if !self.is_fully_funded() {
            missing.push("Funding transaction fully funded");
        }
        if missing.is_empty() {
            debug!("EstablishingState requirements met");
            true
        } else {
            let msg = missing.join(", ");
            debug!("EstablishingState requirements not met: {msg}");
            false
        }
    }

    pub fn to_channel_state(self) -> ChannelState<KC> {
        ChannelState::Establishing(self)
    }

    fn is_fully_funded(&self) -> bool {
        let required = self.metadata.initial_balance().total();
        let result = self.funding_total() >= required;
        trace!(
            "is_fully_funded-- total {}, required {required}: {result}",
            self.funding_total()
        );
        result
    }

    /// This party's complete local material for state 0, ready to be seeded into the open channel's
    /// [`UpdateHistory`].
    ///
    /// `my_preprocess` is empty after a reload, because [`EstablishingState::preprepare_data`] is
    /// `#[serde(skip)]`. That is deliberately not a requirement: a dispute reads the record, our offset, the two
    /// pre-signatures and the peer's binding proof, and none of the preprocessing.
    fn initial_applied_update(&self) -> Result<AppliedUpdate, EstablishError> {
        let mine = self.require_package(&self.my_init_package, "Our initial-state package")?;
        let peer = self.require_package(&self.peer_init_package, "The counterparty's initial-state package")?;
        let omega = self
            .initial_offset
            .as_ref()
            .ok_or_else(|| EstablishError::MissingInformation("Our initial offset ω".into()))?;
        Ok(AppliedUpdate {
            record: self.initial_record()?,
            my_offset: Curve25519Secret::from(**omega),
            my_adapted_signature: mine.adapted_signature.clone(),
            peer_adapted_signature: peer.adapted_signature.clone(),
            peer_binding_proof: peer.binding_proof.clone(),
            my_preprocess: self.preprepare_data.clone(),
            peer_preprocess: self.multisig_wallet.as_ref().and_then(|w| w.peer_pre_process_data()).unwrap_or_default(),
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn next(self) -> Result<EstablishedChannelState<KC>, (Self, LifeCycleError)> {
        debug!("Trying to move from Establishing to Established state");
        if !self.requirements_met() {
            debug!("Cannot change from Establishing to Established because all requirements are not met");
            return Err((self, LifeCycleError::InvalidStateTransition));
        }
        // Built before `self` is taken apart, so a failure can hand the state back intact. Everything it needs
        // was just checked by `requirements_met`, so a failure here is a broken invariant rather than a party
        // that moved too early.
        let initial = match self.initial_applied_update() {
            Ok(update) => update,
            Err(e) => return Err((self, LifeCycleError::InternalError(e.to_string()))),
        };
        debug!("Transitioning to Established wallet state");
        let dynamic = DynamicChannelMetadata::new(self.metadata.initial_balance(), INITIAL_UPDATE_COUNT);
        // Retention depth is clamped to at least one, so state 0 is `latest()` — and `first()` — from the moment
        // the channel opens.
        let mut updates = UpdateHistory::default();
        updates.push(initial);
        let open_channel = EstablishedChannelState {
            metadata: self.metadata,
            dynamic,
            multisig_wallet: self.multisig_wallet.unwrap(),
            funding_transactions: self.funding_transaction_ids,
            updates,
        };
        Ok(open_channel)
    }
}

//----------------------------------  The v2 establishment protocol (Ed25519)  ---------------------------------------//

impl EstablishingState<Ed25519> {
    /// The channel's declared funding outputs, derived locally and in canonical order.
    ///
    /// Each output's one-time key `K_j` and derivation scalar `d_j` come from the shared view key and the
    /// declaration, never from the peer's arithmetic, so both parties derive the same set. It is ordered by
    /// `K_j`'s encoding — a role-independent order, so the two parties' partial vectors line up positionally
    /// without either having to say whose output is whose.
    pub fn funding_outputs(&self) -> Result<Vec<DerivedFundingOutput>, EstablishError> {
        let wallet = self.require_wallet()?;
        let declarations = self.declarations()?;
        let mut outputs = declarations
            .iter()
            .map(|declared| wallet.derive_funding_output(declared))
            .collect::<Result<Vec<_>, _>>()
            .map_err(MultisigWalletError::from)?;
        outputs.sort_unstable_by_key(|out| out.one_time_key.to_bytes());
        Ok(outputs)
    }

    /// This party's share of each funding output's linking tag, to be sent to the counterparty as one message.
    ///
    /// The vector is in the same canonical order as [`funding_outputs`](Self::funding_outputs), which is how
    /// the counterparty knows which partial belongs to which output without being told.
    ///
    /// Neither party holds the shared wallet's spend key, so neither can compute a tag alone; the two partials
    /// sum to it. Each partial travels with a proof that it was derived from the same MuSig share this party
    /// signs with — see [`crate::cryptography::linking_tag`] — because an unproven partial lets the party that
    /// sends second steer the tag, and through it the final channel id, to a value of its choosing.
    pub fn partial_linking_tags(&self) -> Result<Vec<PartialLinkingTag>, EstablishError> {
        let outputs = self.funding_outputs()?;
        let wallet = self.require_wallet()?;
        let tags = outputs
            .iter()
            .map(|out| wallet.partial_linking_tag(out))
            .collect::<Result<Vec<_>, _>>()
            .map_err(MultisigWalletError::from)?;
        Ok(tags)
    }

    /// Bind the channel id to its funding outputs' linking tags and return the resulting final id.
    ///
    /// `peer_partials` is the counterparty's contribution to every tag, in the canonical output order. Both
    /// parties combine the same partials, so both arrive at the same final id. This is the point at which the
    /// provisional `XGT…` id quoted during negotiation is replaced by the final `XGC…` id: it must happen before
    /// any initial-state material is exchanged, because every signature in a [`ChannelInitPackage`] commits to
    /// the channel id.
    ///
    /// A vector of the wrong length is refused before anything is combined, and every contribution proof is
    /// verified before `finalize` sees a single tag. That ordering is the whole point: `finalize` binds the id
    /// for the channel's lifetime and refuses to re-bind, so a tag accepted here can never be corrected — while
    /// a *refused* one leaves the id provisional and the exchange retryable.
    ///
    /// Refuses to re-bind an id that is already final — that would silently rename a channel the counterparty
    /// already refers to by its current id.
    pub fn finalize_channel_id(&mut self, peer_partials: &[PartialLinkingTag]) -> Result<ChannelId, EstablishError> {
        let outputs = self.funding_outputs()?;
        if outputs.len() != peer_partials.len() {
            return Err(EstablishError::PartialLinkingTagCount {
                expected: outputs.len(),
                actual: peer_partials.len(),
            });
        }
        let wallet = self.require_wallet()?;
        // Collected through `Result`, so a single failing proof aborts before any tag is bound.
        let tags = outputs
            .iter()
            .zip(peer_partials)
            .map(|(out, partial)| wallet.linking_tag(out, partial))
            .collect::<Result<Vec<_>, _>>()
            .map_err(MultisigWalletError::from)?;
        let id = self.metadata.channel_id_mut().finalize(tags)?;
        debug!("Channel id bound to {} funding output(s): {id}", outputs.len());
        Ok(id)
    }

    /// The canonical hash of the closing transaction *held by* `holder` at the initial state.
    ///
    /// The two parties hold different closing transactions, so the two adaptor signatures exchanged during
    /// establishment are never over the same bytes.
    ///
    /// Refuses a provisional channel id at the boundary rather than trusting the caller to have gone through
    /// [`generate_init_package`](Self::generate_init_package): this is `pub`, and a [`CloseHash`] over an
    /// `XGT…` id would commit a closing transaction to no funding output.
    pub fn initial_close_hash(&self, holder: ChannelRole) -> Result<CloseHash, EstablishError> {
        let id = self.channel_id();
        id.require_finalized()?;
        let balances = self.metadata.initial_balance();
        let msg = commitment_tx_message(
            &id,
            INITIAL_UPDATE_COUNT,
            holder,
            balances.customer.to_piconero(),
            balances.merchant.to_piconero(),
        );
        Ok(CloseHash::try_from(msg)?)
    }

    /// The close hash the state-0 [`UpdateRecord`] commits to: the canonical hash of *both* exits, so both
    /// parties' halves agree on it.
    ///
    /// [`initial_close_hash`](Self::initial_close_hash) stays per-holder — that is what the adaptor signatures
    /// sign, and the two parties never sign the same closing-transaction bytes. A record carries one hash per
    /// state, so it commits to the pair instead.
    pub fn initial_record_close_hash(&self) -> Result<CloseHash, EstablishError> {
        let id = self.channel_id();
        id.require_finalized()?;
        let balances = self.metadata.initial_balance();
        let msg = commitment_pair_message(
            &id,
            INITIAL_UPDATE_COUNT,
            balances.customer.to_piconero(),
            balances.merchant.to_piconero(),
        );
        Ok(CloseHash::try_from(msg)?)
    }

    /// Sign this party's half of the state-0 [`UpdateRecord`].
    ///
    /// Signed with the **wallet spend key**, not [`channel_secret`](Self::channel_secret) and not the FROST
    /// signing share: `DisputingChannelState` verifies presented records against
    /// `multisig_wallet.my_public_key()` / `peer_public_key()`, and those are the keys the arbiter registers as
    /// `(P_A, P_B)`. It follows that the half does not depend on the FROST preprocessing round trip and can be
    /// signed as soon as the channel id is final.
    fn sign_initial_record_half<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<HalfSignedUpdateRecord, EstablishError> {
        let signing_key = self.require_wallet()?.my_spend_key().as_scalar();
        let half = HalfSignedUpdateRecord::sign(
            self.channel_id(),
            INITIAL_UPDATE_COUNT,
            self.initial_record_close_hash()?,
            HasRole::role(self),
            signing_key,
            rng,
        )?;
        Ok(half)
    }

    /// Generate this party's [`ChannelInitPackage`]: a fresh offset `ω`, the adaptor signature over the
    /// *counterparty's* closing transaction, `ω` sealed to `m = (channel_id, 0)` under the arbiter's master key,
    /// the binding proof tying the two together, and our half of the state-0 record.
    ///
    /// Requires the shared wallet, a final channel id, and a completed FROST partial signature
    /// ([`prepare_initial_transaction`](Self::prepare_initial_transaction) followed by
    /// [`receive_peer_preprocess_data`](Self::receive_peer_preprocess_data)): the adaptor signature adapts *that*
    /// partial signature, so revealing `ω` yields a share the wallet can complete into a broadcastable close.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage, EstablishError> {
        self.require_final_channel_id()?;
        let signing_key = self.wallet_signing_key()?;
        let peer_close_hash = self.initial_close_hash(HasRole::role(self).other())?;
        let record_half = self.sign_initial_record_half(rng)?;
        let (package, omega) = ChannelInitPackage::create(
            &self.channel_id(),
            &peer_close_hash,
            &signing_key,
            record_half,
            self.metadata.arbiter_configuration().master_public_key(),
            self.binding_proof_params,
            rng,
        )?;
        self.initial_offset = Some(omega.into());
        self.my_init_package = Some(package.clone());
        debug!("Initial-state package generated for state {INITIAL_UPDATE_COUNT}");
        Ok(package)
    }

    /// Verify the counterparty's [`ChannelInitPackage`] and, only if every check passes, accept the initial
    /// state.
    ///
    /// The checks are the ones the sequence diagram fixes: the adaptor signature verifies under the
    /// counterparty's wallet key over *our* closing transaction, the binding proof holds for
    /// `m = (channel_id, 0)` and targets exactly that signature's adaptor point `Q`, and the record half is the
    /// counterparty's signature over state 0 of this channel.
    ///
    /// All or nothing: a package that fails any check leaves `peer_init_package` untouched, so nothing
    /// half-accepted can reach [`initial_record`](Self::initial_record).
    pub fn receive_peer_init_package(&mut self, package: ChannelInitPackage) -> Result<(), EstablishError> {
        self.require_final_channel_id()?;
        let peer_pubkey = self.require_wallet()?.peer_public_key().as_point();
        let own_close_hash = self.initial_close_hash(HasRole::role(self))?;
        let record_close_hash = self.initial_record_close_hash()?;
        package.verify(
            &self.channel_id(),
            &own_close_hash,
            &record_close_hash,
            HasRole::role(self),
            &peer_pubkey,
            self.metadata.arbiter_configuration().master_public_key(),
        )?;
        debug!("The counterparty's initial-state package verified; accepting state {INITIAL_UPDATE_COUNT}");
        self.peer_init_package = Some(package);
        Ok(())
    }

    /// The wallet signing share this party adapts. Available once the FROST preprocessing round trip has
    /// completed.
    fn wallet_signing_key(&self) -> Result<XmrScalar, EstablishError> {
        self.require_wallet()?.my_signing_share().ok_or_else(|| {
            EstablishError::MissingInformation(
                "Wallet signing share — the initial commitment transaction has not been partially signed".into(),
            )
        })
    }

    fn require_final_channel_id(&self) -> Result<(), EstablishError> {
        if self.metadata.channel_id().is_finalized() {
            Ok(())
        } else {
            Err(EstablishError::MissingInformation(
                "Final channel id — the funding outputs' linking tags have not been bound to it yet".into(),
            ))
        }
    }
}

// --- HasRole implementation ---

impl<KC> HasRole for EstablishingState<KC>
where
    KC: Ciphersuite,
{
    fn role(&self) -> ChannelRole {
        self.metadata.role()
    }
}

// ---------------------------------- From conversions for proposal states ------------------------------------------

impl<KC> From<AwaitingProposalResponse<KC>> for EstablishingState<KC>
where
    KC: Ciphersuite,
{
    fn from(state: AwaitingProposalResponse<KC>) -> Self {
        EstablishingState::new(state.metadata, state.channel_secret, state.partial_spend_key)
    }
}

impl<KC> From<AwaitingConfirmation<KC>> for EstablishingState<KC>
where
    KC: Ciphersuite,
{
    fn from(state: AwaitingConfirmation<KC>) -> Self {
        EstablishingState::new(state.metadata, state.channel_secret, state.partial_spend_key)
    }
}

//---------------------------------- Role-Specific EstablishingState Wrappers ------------------------------------------

/// Ephemeral wrapper around [`EstablishingState`] for merchant-specific protocol steps.
///
/// Constructed on-demand when the merchant needs to perform establishment operations,
/// then unwrapped via [`into_inner`](MerchantEstablishing::into_inner) to return the state.
pub struct MerchantEstablishing {
    inner: EstablishingState,
    wallet_setup: MerchantSetup<MultisigWalletKeyNegotiation>,
}

impl MerchantEstablishing {
    /// Wrap an `EstablishingState`, returning an error if the state is not for a merchant.
    pub fn new(state: EstablishingState, rpc_url: impl Into<String>) -> Result<Self, EstablishError> {
        let role = HasRole::role(&state);
        if role != ChannelRole::Merchant {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: role });
        }
        let network = state.metadata.network();
        let w = MultisigWalletKeyNegotiation::new(
            ChannelRole::Merchant,
            network,
            state.wallet_partial_spend_key.clone(),
            rpc_url,
        );
        let wallet_setup = MerchantSetup::new(w).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        Ok(Self { inner: state, wallet_setup })
    }

    /// Unwrap and return the underlying `EstablishingState`.
    pub fn into_inner(self) -> EstablishingState {
        self.inner
    }

    /// Borrow the underlying state.
    pub fn state(&self) -> &EstablishingState {
        &self.inner
    }

    /// Mutably borrow the underlying state.
    pub fn state_mut(&mut self) -> &mut EstablishingState {
        &mut self.inner
    }

    /// Generate and return a commitment to the merchant's public key.
    ///
    /// Must only be called once (transitions the wallet setup from `Initialized` to `CommitmentSent`).
    pub fn wallet_public_key_commitment(&mut self) -> Result<PublicKeyCommitment, EstablishError> {
        self.wallet_setup.commit_to_public_key().map_err(|e| EstablishError::MissingInformation(e.to_string()))
    }

    /// Returns the merchant's "partial" public key for the multisig wallet
    pub fn wallet_public_key(&self) -> SharedPublicKey {
        self.wallet_setup.wallet().shared_public_key()
    }

    pub fn set_customer_wallet_public_key(&mut self, key: SharedPublicKey) -> Result<(), EstablishError> {
        if key.role() != ChannelRole::Customer {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: key.role() });
        }
        self.wallet_setup.receive_peer_key(key).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.wallet_setup.complete().map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        let keyring = MultisigWallet::try_from(self.wallet_setup.wallet().clone())
            .map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.inner.multisig_wallet = Some(keyring);
        Ok(())
    }

    /// Prepare the initial commitment transaction for signing.
    ///
    /// Delegates to [`EstablishingState::prepare_initial_transaction`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        self.inner.prepare_initial_transaction().await
    }

    /// Returns a copy of the preprocess data for exchange with the peer.
    pub fn preprocess_data(&self) -> Result<Vec<u8>, EstablishError> {
        self.inner.preprepare_data()
    }

    /// Receive peer's preprocess data and complete partial signing.
    ///
    /// Delegates to [`EstablishingState::receive_peer_preprocess_data`].
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        self.inner.receive_peer_preprocess_data(data)
    }

    /// Declare the funding output the merchant will contribute, if it funds this channel.
    pub fn declare_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        self.inner.declare_funding_output(output)
    }

    /// Record the customer's funding-output declaration.
    pub fn receive_customer_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        self.inner.receive_peer_funding_output(output)
    }

    /// The merchant's share of every funding output's linking tag, with contribution proofs, to send to the
    /// customer.
    pub fn partial_linking_tags(&self) -> Result<Vec<PartialLinkingTag>, EstablishError> {
        self.inner.partial_linking_tags()
    }

    /// Bind the channel id to its funding outputs' tags, combining the customer's verified partials with the
    /// merchant's own.
    pub fn finalize_channel_id(
        &mut self,
        customer_partials: &[PartialLinkingTag],
    ) -> Result<ChannelId, EstablishError> {
        self.inner.finalize_channel_id(customer_partials)
    }

    /// Generate the merchant's [`ChannelInitPackage`] for the initial channel state.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage, EstablishError> {
        self.inner.generate_init_package(rng)
    }

    /// Verify and accept the customer's [`ChannelInitPackage`].
    pub fn receive_customer_init_package(&mut self, package: ChannelInitPackage) -> Result<(), EstablishError> {
        self.inner.receive_peer_init_package(package)
    }

    /// Stores the details of the funding transaction, passing through to the underlying EstablishingState call.
    pub(crate) fn funding_tx_confirmed(&mut self, tx: TransactionRecord) {
        self.inner.funding_tx_confirmed(tx);
    }
}

/// Ephemeral wrapper around [`EstablishingState`] for customer-specific protocol steps.
///
/// Constructed on-demand when the customer needs to perform establishment operations,
/// then unwrapped via [`into_inner`](CustomerEstablishing::into_inner) to return the state.
pub struct CustomerEstablishing {
    inner: EstablishingState,
    wallet_setup: CustomerSetup<MultisigWalletKeyNegotiation>,
}

impl CustomerEstablishing {
    /// Wrap an `EstablishingState`, returning an error if the state is not for a customer.
    pub fn new(state: EstablishingState, rpc_url: impl Into<String>) -> Result<Self, EstablishError> {
        let role = HasRole::role(&state);
        if role != ChannelRole::Customer {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Customer, got: role });
        }
        let network = state.metadata.network();
        let w = MultisigWalletKeyNegotiation::new(
            ChannelRole::Customer,
            network,
            state.wallet_partial_spend_key.clone(),
            rpc_url,
        );
        let wallet_setup = CustomerSetup::new(w).map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        Ok(Self { inner: state, wallet_setup })
    }

    /// Unwrap and return the underlying `EstablishingState`.
    pub fn into_inner(self) -> EstablishingState {
        self.inner
    }

    /// Borrow the underlying state.
    pub fn state(&self) -> &EstablishingState {
        &self.inner
    }

    /// Mutably borrow the underlying state.
    pub fn state_mut(&mut self) -> &mut EstablishingState {
        &mut self.inner
    }

    /// Store the merchant's public key commitment.
    ///
    /// Must only be called once (transitions the wallet setup from `AwaitingPeerCommitment` to `AwaitingPeerKey`).
    pub fn set_merchant_wallet_public_key_commitment(
        &mut self,
        commitment: PublicKeyCommitment,
    ) -> Result<(), EstablishError> {
        self.wallet_setup.receive_commitment(commitment).map_err(|e| EstablishError::MissingInformation(e.to_string()))
    }

    /// Returns the customer's "partial" public key for the multisig wallet
    pub fn wallet_public_key(&self) -> SharedPublicKey {
        self.wallet_setup.wallet().shared_public_key()
    }

    /// Set the merchant's "partial" public key for the multisig wallet.
    pub fn set_merchant_wallet_public_key(&mut self, key: SharedPublicKey) -> Result<(), EstablishError> {
        if key.role() != ChannelRole::Merchant {
            return Err(EstablishError::WrongRole { expected: ChannelRole::Merchant, got: key.role() });
        }
        self.wallet_setup.receive_peer_key(key)?;
        self.wallet_setup.verify_against_commitment()?;
        let keyring = MultisigWallet::try_from(self.wallet_setup.wallet().clone())
            .map_err(|e| EstablishError::MissingInformation(e.to_string()))?;
        self.inner.multisig_wallet = Some(keyring);
        Ok(())
    }

    /// Prepare the initial commitment transaction for signing.
    ///
    /// Delegates to [`EstablishingState::prepare_initial_transaction`].
    pub async fn prepare_initial_transaction(&mut self) -> Result<(), EstablishError> {
        self.inner.prepare_initial_transaction().await
    }

    /// Returns a copy of the preprocess data for exchange with the peer.
    pub fn preprocess_data(&self) -> Result<Vec<u8>, EstablishError> {
        self.inner.preprepare_data()
    }

    /// Receive peer's preprocess data and complete partial signing.
    ///
    /// Delegates to [`EstablishingState::receive_peer_preprocess_data`].
    pub fn receive_peer_preprocess_data(&mut self, data: Vec<u8>) -> Result<(), EstablishError> {
        self.inner.receive_peer_preprocess_data(data)
    }

    /// Declare the funding output the customer will contribute.
    pub fn declare_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        self.inner.declare_funding_output(output)
    }

    /// Record the merchant's funding-output declaration, for a channel the merchant also funds.
    pub fn receive_merchant_funding_output(&mut self, output: FundingOutputRef) -> Result<(), EstablishError> {
        self.inner.receive_peer_funding_output(output)
    }

    /// The customer's share of every funding output's linking tag, with contribution proofs, to send to the
    /// merchant.
    pub fn partial_linking_tags(&self) -> Result<Vec<PartialLinkingTag>, EstablishError> {
        self.inner.partial_linking_tags()
    }

    /// Bind the channel id to its funding outputs' tags, combining the merchant's verified partials with the
    /// customer's own.
    pub fn finalize_channel_id(
        &mut self,
        merchant_partials: &[PartialLinkingTag],
    ) -> Result<ChannelId, EstablishError> {
        self.inner.finalize_channel_id(merchant_partials)
    }

    /// Generate the customer's [`ChannelInitPackage`] for the initial channel state.
    pub fn generate_init_package<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<ChannelInitPackage, EstablishError> {
        self.inner.generate_init_package(rng)
    }

    /// Verify and accept the merchant's [`ChannelInitPackage`].
    pub fn receive_merchant_init_package(&mut self, package: ChannelInitPackage) -> Result<(), EstablishError> {
        self.inner.receive_peer_init_package(package)
    }

    /// Stores the details of the funding transaction, passing through to the underlying EstablishingState call.
    pub(crate) fn funding_tx_confirmed(&mut self, tx: TransactionRecord) {
        self.inner.funding_tx_confirmed(tx);
    }
}

// --- LifeCycle implementation ---

use crate::state_machine::lifecycle::{LifeCycle, LifecycleStage};
use crate::state_machine::{CustomerSetup, MerchantSetup, SetupState};
use crate::wallet::multisig_wallet::MultisigWallet;

impl<KC> LifeCycle<KC> for EstablishingState<KC>
where
    KC: Ciphersuite,
{
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Establishing
    }

    fn metadata(&self) -> &StaticChannelMetadata<KC> {
        &self.metadata
    }

    fn balance(&self) -> Balances {
        self.metadata.initial_balance()
    }

    fn wallet_address(&self) -> Option<String> {
        self.multisig_address()
    }
}
