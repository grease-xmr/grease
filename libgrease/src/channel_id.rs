use crate::arbiter::ArbiterConfiguration;
use crate::balance::Balances;
use crate::helpers::group_element_to_hex;
use crate::monero::data_objects::ClosingAddresses;
use blake2::Blake2b512;
use crate::cryptography::SecureDigest;
use crate::Ed25519;
use ciphersuite::group::{Group, GroupEncoding};
use ciphersuite::Ciphersuite;
use digest::OutputSizeUser;
use flexible_transcript::{DigestTranscript, Transcript};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::str::FromStr;
use thiserror::Error;

/// Error returned when parsing a [`ChannelId`] from a string fails.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChannelIdParseError {
    #[error("Invalid channel ID format: expected 65 characters starting with 'XGC' or 'XGT', got {0} characters")]
    InvalidLength(usize),
    #[error("Invalid channel ID format: must start with 'XGC' (final) or 'XGT' (provisional)")]
    InvalidPrefix,
    #[error("Invalid channel ID format: contains non-hexadecimal characters after prefix")]
    InvalidHex,
}

/// Error returned when a provisional (`XGT…`) channel id reaches a boundary that turns an id into signed or
/// sealed bytes.
///
/// A provisional id commits to no funding output, so a statement, signature or record over it would not be bound
/// to one channel. The state machine never routes one here on any reachable path; this error is the boundary's
/// own refusal, so a future caller — the v2 wire layer above all — cannot rely on that discipline by accident.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("channel id {0} is provisional: it commits to no funding output, so nothing may be signed or sealed against it")]
pub struct ProvisionalChannelIdError(pub ChannelId);

/// Error returned when binding a [`ChannelIdMetadata`] to its funding outputs is not allowed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ChannelIdFinalizeError {
    #[error("This channel id is already bound to its funding outputs; re-binding would change the channel id")]
    AlreadyFinalized,
    #[error("A channel is funded by at least one output, so a final id commits to at least one linking tag")]
    NoLinkingTags,
    #[error("A funding linking tag is the identity element and identifies no funding output")]
    DegenerateLinkingTag,
    #[error("Two funding linking tags are equal, so the two funders declared the same output")]
    DuplicateLinkingTag,
}

/// A 65-character string uniquely identifying a payment channel.
///
/// Format: a 3-character prefix + the first 31 bytes of the channel hash as hex (62 chars). The prefix is
/// `XGC` when the id commits to a funding output and `XGT` while the channel is still being negotiated and
/// no funding output exists yet. A holder of nothing but the string can therefore tell which kind of id it
/// has, which is what makes a provisional id safe to quote during negotiation.
///
/// With respect to the *channel-id transcript* the prefix is a display-layer tag only: it is **not**
/// absorbed, and `compute_hash` never sees it. It does not need to be. A provisional and a final id
/// already differ in their hex digits, because the transcript absorbs the funding linking tags as an empty
/// message in the one case and as their concatenation in the other. The prefix only makes that difference
/// legible to a party that does not hold the metadata.
///
/// Downstream of the id, the prefix carries real cryptographic weight. Every message transcript that takes a
/// channel id — the dispute statement ([`statement_for`][crate::arbiter::client::statement_for]), the
/// adapter-signature and update-record messages, the establish/update payload messages, the
/// commitment-transaction message — absorbs the id as this *prefixed* string, via [`as_str`][ChannelId::as_str].
/// That makes the prefix full domain separation between a provisional and a final channel at every point where
/// an id becomes signed or sealed bytes: the two statements differ in the first three bytes of the message by
/// construction, whatever their hex halves do. Never absorb a "normalised" id — the hex half, or the raw hash
/// bytes — into such a transcript: that would silently delete this separation without disturbing the id
/// transcript's own vectors.
///
/// This is the human-readable representation of a [`ChannelIdMetadata`]. It can be used as a key
/// in maps, displayed to users, and transmitted over the network.
///
/// # Example
///
/// ```
/// use libgrease::channel_id::ChannelId;
/// use std::str::FromStr;
///
/// let id = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
/// assert_eq!(id.as_str(), "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383");
/// assert!(id.is_finalized());
///
/// let provisional = ChannelId::from_str("XGT4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
/// assert!(!provisional.is_finalized());
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(String);

impl ChannelId {
    /// The prefix for a channel ID that commits to a funding output.
    pub const PREFIX_FINAL: &'static str = "XGC";

    /// The prefix for a provisional channel ID, used while a channel is negotiated and no funding output
    /// exists yet.
    pub const PREFIX_PROVISIONAL: &'static str = "XGT";

    /// The total length of a channel ID string (3 char prefix + 62 hex chars).
    pub const LENGTH: usize = 65;

    /// Create a new `ChannelId` from a [`ChannelIdMetadata`].
    pub fn from_channel_id_metadata<C, D>(id: &ChannelIdMetadata<C, D>) -> Self
    where
        C: Ciphersuite,
        D: Send + Clone + SecureDigest,
    {
        Self(id.as_hex())
    }

    /// Returns the channel ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this id commits to a funding output, read off its prefix.
    ///
    /// Every `ChannelId` is validated on construction, so the prefix is one of the two known ones and this
    /// is exact rather than a guess.
    pub fn is_finalized(&self) -> bool {
        self.0.starts_with(Self::PREFIX_FINAL)
    }

    /// Refuse this id unless it commits to a funding output.
    ///
    /// The one-line guard for the functions that turn a channel id into signed or sealed bytes
    /// ([`statement_for`][crate::arbiter::client::statement_for],
    /// [`adapter_signature_message`][crate::grease_protocol::adapter_signature::adapter_signature_message],
    /// [`HalfSignedUpdateRecord::sign`][crate::grease_protocol::update_record::HalfSignedUpdateRecord::sign] and
    /// `EstablishingState::initial_close_hash`): each of them rejects a provisional id here, at the boundary,
    /// rather than trusting every caller to have gone through the state machine's chokepoints.
    pub fn require_finalized(&self) -> Result<(), ProvisionalChannelIdError> {
        if self.is_finalized() {
            Ok(())
        } else {
            Err(ProvisionalChannelIdError(self.clone()))
        }
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ChannelId({})", self.0)
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ChannelId {
    type Err = ChannelIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != Self::LENGTH {
            return Err(ChannelIdParseError::InvalidLength(s.len()));
        }
        if !s.starts_with(Self::PREFIX_FINAL) && !s.starts_with(Self::PREFIX_PROVISIONAL) {
            return Err(ChannelIdParseError::InvalidPrefix);
        }
        // Validate that the hex portion is valid
        hex::decode(&s[3..]).map_err(|_| ChannelIdParseError::InvalidHex)?;
        Ok(Self(s.to_string()))
    }
}

impl AsRef<str> for ChannelId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ChannelId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<ChannelId> for String {
    fn from(id: ChannelId) -> Self {
        id.0
    }
}

impl TryFrom<&str> for ChannelId {
    type Error = ChannelIdParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<String> for ChannelId {
    type Error = ChannelIdParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

/// The unique identifier for a payment channel.
///
/// The channel ID is derived from a digest transcript hash (domain separator: `"Grease ChannelId v2"`)
/// over the following fields, in order:
/// - `merchant_key`: The merchant's Curve25519 public key (32 bytes, compressed, little-endian)
/// - `customer_key`: The customer's Curve25519 public key (32 bytes, compressed, little-endian)
/// - `merchant_balance`: The merchant's initial balance in piconero (u64, little-endian)
/// - `customer_balance`: The customer's initial balance in piconero (u64, little-endian)
/// - `merchant_closing_address`: The merchant's Monero closing address, as a Base58 string
/// - `customer_closing_address`: The customer's Monero closing address, as a Base58 string
/// - `funding_linking_tags`: The channel's funding linking tags, one per funding output — each 32 bytes,
///   compressed, little-endian, sorted ascending by that encoding and concatenated
/// - `merchant_nonce`: The merchant's channel nonce (u64, little-endian)
/// - `customer_nonce`: The customer's channel nonce (u64, little-endian)
///
/// The arbiter the parties agree on is deliberately **not** committed to: it sees the id only as an opaque
/// label, and that binding would cost it knowledge of the channel for no benefit.
///
/// A channel is funded by one output per funding party, and each output contributes the tag `L_j` that its
/// spend will publish as a key image. The tags are absorbed *sorted*, so the id does not record which party
/// contributed which output — attribution lives in the declaration and its out-proof, not in the id.
///
/// # Provisional and final ids
///
/// The tags only exist once the funding outputs are declared, so metadata built during negotiation is
/// *provisional*: they are absent and the transcript absorbs an empty `funding_linking_tags` message.
/// Transcript messages are length-prefixed, so an absent tag can never collide with a present one — nor can
/// one channel's single tag collide with another's pair. [`ChannelIdMetadata::finalize`] supplies the tags and
/// recomputes the hash, yielding the final id.
///
/// Including the tags gives the two properties the arbiter relies on. The id *commits to* them, so a record
/// carrying it is bound to one set of funding outputs and cannot be replayed against another channel; and the
/// id *hides* them, because the two random nonces blind the hash.
///
/// # Nonce freshness is mandatory
///
/// The nonces also carry a uniqueness duty. Each party must draw its nonce uniformly at random per channel:
/// a fresh nonce is that party's *unilateral* guarantee that no two of its channels share an id, whatever
/// the counterparty does, and a party that reuses its own nonce bears the resulting collision risk itself —
/// two ids collide only if *both* parties repeat their nonces along with every other field. Every other
/// transcript field may legitimately repeat (the merchant's half comes from a reusable out-of-band seed), so
/// without the nonces id uniqueness would rest on the funding outputs alone.
///
/// The digest type `D` must produce at least 32 bytes of output. The default (`Blake2b512`)
/// produces a 64-byte hash. The human-readable channel ID format is a 3-character prefix — `XGC` once the
/// id is final, `XGT` while it is provisional — followed by the first 31 bytes of the hash encoded as hex
/// (65 characters total). That prefix is a display-layer tag: `compute_hash` does not
/// absorb it, and does not need to, because the presence or absence of the tags already separates the two
/// hashes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ChannelIdMetadata<C: Ciphersuite = Ed25519, D = Blake2b512> {
    /// The merchant's public key, #Pm, from which the shared channel secret is derived.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    merchant_key: C::G,
    /// The customer's public key, #Pc, from which the shared channel secret is derived.
    #[serde(serialize_with = "crate::helpers::serialize_ge", deserialize_with = "crate::helpers::deserialize_ge")]
    customer_key: C::G,
    initial_balance: Balances,
    closing_addresses: ClosingAddresses,
    /// The arbiter the parties agreed on for this channel. Not part of the channel id transcript.
    arbiter_config: ArbiterConfiguration,
    /// The merchant's contribution to the channel nonce. Must be drawn uniformly at random — see
    /// [`ChannelIdMetadata`], *Nonce freshness is mandatory*.
    merchant_nonce: u64,
    /// The customer's contribution to the channel nonce. Must be drawn uniformly at random — see
    /// [`ChannelIdMetadata`], *Nonce freshness is mandatory*.
    customer_nonce: u64,
    /// The channel's funding linking tags, one per funding output, held in ascending-encoding order. `None`
    /// until the funding outputs are declared and the id is finalized.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "crate::helpers::option_serialize_ge_seq",
        deserialize_with = "crate::helpers::option_deserialize_ge_seq"
    )]
    linking_tags: Option<Vec<C::G>>,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    hashed_id: Vec<u8>,
    _phantom: PhantomData<D>,
}

impl<C: Ciphersuite, D> ChannelIdMetadata<C, D>
where
    D: Send + Clone + SecureDigest,
{
    /// Create a new channel ID from the given parameters.
    ///
    /// See [`ChannelIdMetadata`] for the full specification of the hash computation.
    ///
    /// The generic parameter `D` controls the digest algorithm and output size.
    /// The digest must produce at least 32 bytes of output (enforced at compile time).
    ///
    /// # Compile-time safety
    ///
    /// A digest of 32 bytes or wider satisfies [`SecureDigest`](crate::cryptography::SecureDigest):
    ///
    /// ```
    /// use blake2::Blake2b;
    /// use digest::consts::U32;
    /// use libgrease::arbiter::ArbiterConfiguration;
    /// use libgrease::balance::Balances;
    /// use libgrease::channel_id::ChannelIdMetadata;
    /// use libgrease::monero::data_objects::ClosingAddresses;
    /// use libgrease::{Ed25519, XmrPoint};
    ///
    /// fn compiles(
    ///     merchant_key: XmrPoint,
    ///     customer_key: XmrPoint,
    ///     balance: Balances,
    ///     closing: ClosingAddresses,
    ///     arbiter: ArbiterConfiguration,
    /// ) {
    ///     let _ = ChannelIdMetadata::<Ed25519, Blake2b<U32>>::new(
    ///         merchant_key, customer_key, balance, closing, arbiter, 0, 0,
    ///     );
    /// }
    /// ```
    ///
    /// One narrower than that does not, and the identical call fails to compile:
    ///
    /// ```compile_fail
    /// use blake2::Blake2b;
    /// use digest::consts::U16;
    /// use libgrease::arbiter::ArbiterConfiguration;
    /// use libgrease::balance::Balances;
    /// use libgrease::channel_id::ChannelIdMetadata;
    /// use libgrease::monero::data_objects::ClosingAddresses;
    /// use libgrease::{Ed25519, XmrPoint};
    ///
    /// // `Blake2b<U16>` produces 16 bytes, so it does not satisfy `SecureDigest`.
    /// fn wont_compile(
    ///     merchant_key: XmrPoint,
    ///     customer_key: XmrPoint,
    ///     balance: Balances,
    ///     closing: ClosingAddresses,
    ///     arbiter: ArbiterConfiguration,
    /// ) {
    ///     let _ = ChannelIdMetadata::<Ed25519, Blake2b<U16>>::new(
    ///         merchant_key, customer_key, balance, closing, arbiter, 0, 0,
    ///     );
    /// }
    /// ```
    pub fn new(
        merchant_key: C::G,
        customer_key: C::G,
        initial_balance: Balances,
        closing_addresses: ClosingAddresses,
        arbiter_config: ArbiterConfiguration,
        merchant_nonce: u64,
        customer_nonce: u64,
    ) -> Self {
        let mut id = ChannelIdMetadata {
            merchant_key,
            customer_key,
            initial_balance,
            closing_addresses,
            arbiter_config,
            merchant_nonce,
            customer_nonce,
            linking_tags: None,
            hashed_id: Vec::new(),
            _phantom: PhantomData,
        };
        id.hashed_id = id.compute_hash();
        id
    }

    /// Bind this channel id to its funding outputs' linking tags and return the resulting final id.
    ///
    /// Until this is called the id is *provisional*: it identifies the negotiated channel parameters but
    /// commits to no funding output, so nothing bound to it can be replayed against a different channel only
    /// because the two share parameters. Finalizing recomputes the hash over the full v2 transcript, so the
    /// final id always differs from the provisional one.
    ///
    /// The tags are sorted by their encoding before being absorbed, so the id records *which* outputs fund the
    /// channel but not which party contributed which. That is deliberate: attribution belongs to the funding
    /// declaration and its out-proof, and putting it in the id would leak the split to anyone holding the
    /// metadata without buying the arbiter anything.
    ///
    /// A channel id is bound to its funding outputs exactly once. Finalizing an already-finalized id would
    /// silently rename a channel that peers, records and stored state already refer to by its current id, so
    /// it is rejected rather than left to caller discipline.
    ///
    /// Three degenerate inputs are refused. An empty vector, because a channel is funded by at least one
    /// output and an id over no tags is the provisional id with a final prefix. Two equal tags, because that
    /// means the two funders declared the same output — no honest channel produces it, and absorbing it would
    /// let a dual-funded channel masquerade as one funded twice over. And the identity element, which is a
    /// backstop rather than the defence: the real guarantee that a tag is the shared wallet's comes from the
    /// per-party contribution proof verified before the partials are combined
    /// ([`crate::cryptography::linking_tag`]). It is kept because it costs one comparison, is independent of
    /// that machinery, and applies to every caller on every curve — an identity tag is the one value an
    /// attacker could still force to be *shared* between two channels without knowing any secret, since it is
    /// the sum of any partial and its negation. Torsion rejection cannot live here (`C::G` is an abstract
    /// prime-order group with no cofactor to speak of) and is applied on the Ed25519 path, where the wallet
    /// checks both the peer's partial and each combined tag.
    pub fn finalize(&mut self, linking_tags: Vec<C::G>) -> Result<ChannelId, ChannelIdFinalizeError> {
        if self.linking_tags.is_some() {
            return Err(ChannelIdFinalizeError::AlreadyFinalized);
        }
        if linking_tags.is_empty() {
            return Err(ChannelIdFinalizeError::NoLinkingTags);
        }
        if linking_tags.iter().any(|tag| bool::from(tag.is_identity())) {
            return Err(ChannelIdFinalizeError::DegenerateLinkingTag);
        }
        let mut sorted = linking_tags;
        sorted.sort_unstable_by(|a, b| a.to_bytes().as_ref().cmp(b.to_bytes().as_ref()));
        if sorted.windows(2).any(|pair| pair[0].to_bytes().as_ref() == pair[1].to_bytes().as_ref()) {
            return Err(ChannelIdFinalizeError::DuplicateLinkingTag);
        }
        self.linking_tags = Some(sorted);
        self.hashed_id = self.compute_hash();
        Ok(self.name())
    }

    /// The channel's funding linking tags in ascending-encoding order, or `None` while the id is provisional.
    pub fn linking_tags(&self) -> Option<&[C::G]> {
        self.linking_tags.as_deref()
    }

    /// Whether this id commits to its funding outputs. A provisional id does not.
    pub fn is_finalized(&self) -> bool {
        self.linking_tags.is_some()
    }

    /// Hash the v2 transcript. A provisional id absorbs an empty `funding_linking_tags` message; since the
    /// transcript length-prefixes every message, that can collide neither with a present tag nor with a
    /// different number of them.
    fn compute_hash(&self) -> Vec<u8> {
        self.hash_with_tags(self.linking_tags.as_deref())
    }

    /// Hash the v2 transcript with `funding_linking_tags` absorbed as `tags` — absent for the provisional form.
    ///
    /// `tags` must already be sorted; [`finalize`](Self::finalize) is the only thing that stores them.
    fn hash_with_tags(&self, tags: Option<&[C::G]>) -> Vec<u8> {
        let amount_mer = self.initial_balance.merchant.to_piconero().to_le_bytes();
        let amount_cust = self.initial_balance.customer.to_piconero().to_le_bytes();
        // The whole concatenation is one length-prefixed transcript message, so a single tag cannot be read as
        // two, nor two as one.
        let linking_tags = tags.map_or_else(Vec::new, |tags| {
            tags.iter().flat_map(|tag| tag.to_bytes().as_ref().to_vec()).collect::<Vec<u8>>()
        });

        let mut transcript = DigestTranscript::<D>::new(b"Grease ChannelId v2");
        transcript.append_message(b"merchant_key", self.merchant_key.to_bytes());
        transcript.append_message(b"customer_key", self.customer_key.to_bytes());
        transcript.append_message(b"merchant_balance", amount_mer);
        transcript.append_message(b"customer_balance", amount_cust);
        // The specification is normative here: the closing addresses are absorbed as Base58 strings, not as
        // the raw address payload that `Address::as_bytes` returns.
        transcript.append_message(b"merchant_closing_address", self.closing_addresses.merchant().to_string());
        transcript.append_message(b"customer_closing_address", self.closing_addresses.customer().to_string());
        transcript.append_message(b"funding_linking_tags", &linking_tags);
        transcript.append_message(b"merchant_nonce", self.merchant_nonce.to_le_bytes());
        transcript.append_message(b"customer_nonce", self.customer_nonce.to_le_bytes());

        let challenge = transcript.challenge(b"channel_id");
        let output_size = <D as OutputSizeUser>::output_size();
        challenge[..output_size].to_vec()
    }

    pub fn merchant_key(&self) -> &C::G {
        &self.merchant_key
    }

    pub fn customer_key(&self) -> &C::G {
        &self.customer_key
    }

    pub fn initial_balance(&self) -> Balances {
        self.initial_balance
    }

    pub fn closing_addresses(&self) -> &ClosingAddresses {
        &self.closing_addresses
    }

    pub fn arbiter_config(&self) -> &ArbiterConfiguration {
        &self.arbiter_config
    }

    pub fn merchant_nonce(&self) -> u64 {
        self.merchant_nonce
    }

    pub fn customer_nonce(&self) -> u64 {
        self.customer_nonce
    }

    pub fn hash(&self) -> &[u8] {
        &self.hashed_id
    }

    /// Returns the channel ID as a 65-character string: a 3-character prefix + the first 31 bytes of the
    /// hash in hex.
    ///
    /// The prefix is [`ChannelId::PREFIX_FINAL`] (`XGC`) once the id is bound to its funding outputs and
    /// [`ChannelId::PREFIX_PROVISIONAL`] (`XGT`) while it is still provisional. The prefix is a display-layer
    /// tag and is **not** absorbed into the transcript — see [`ChannelId`] for why that is sufficient.
    pub fn as_hex(&self) -> String {
        let prefix = if self.is_finalized() { ChannelId::PREFIX_FINAL } else { ChannelId::PREFIX_PROVISIONAL };
        format!("{prefix}{}", hex::encode(&self.hash()[..31]))
    }

    /// Returns the channel ID as a [`ChannelId`].
    ///
    /// This is the preferred way to get the channel identifier for use as a key or display.
    pub fn name(&self) -> ChannelId {
        ChannelId::from_channel_id_metadata(self)
    }

    /// The provisional (`XGT…`) id this channel was negotiated under — the *invariant* form of the id.
    ///
    /// The provisional transcript hashes every negotiated field and no funding tag, so it is fixed from the
    /// proposal onward: [`finalize`](Self::finalize) recomputes the *current* id over a transcript that
    /// absorbs the tags, but recomputing the tagless transcript here yields the same value before and after.
    /// Storage keys a channel's state by this id (see [`FileStore`](crate::storage::FileStore)), so a
    /// channel's record never moves when its current id changes and no orphaned snapshot can survive
    /// finalization. It is a storage handle only — never sign or seal against it
    /// ([`ChannelId::require_finalized`]).
    pub fn provisional_name(&self) -> ChannelId {
        match self.is_finalized() {
            false => self.name(),
            true => {
                let hash = self.hash_with_tags(None);
                ChannelId(format!("{}{}", ChannelId::PREFIX_PROVISIONAL, hex::encode(&hash[..31])))
            }
        }
    }
}

impl<C: Ciphersuite, D> Debug for ChannelIdMetadata<C, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelId")
            .field("merchant_key", &group_element_to_hex::<C>(&self.merchant_key))
            .field("customer_key", &group_element_to_hex::<C>(&self.customer_key))
            .field("initial balance (merchant)", &self.initial_balance.merchant)
            .field("initial balance (customer)", &self.initial_balance.customer)
            .field("merchant_nonce", &self.merchant_nonce)
            .field("customer_nonce", &self.customer_nonce)
            .field(
                "linking_tags",
                &self.linking_tags.as_ref().map(|tags| tags.iter().map(group_element_to_hex::<C>).collect::<Vec<_>>()),
            )
            .field("hashed_id", &hex::encode(&self.hashed_id))
            .finish()
    }
}

impl<C: Ciphersuite, D> Display for ChannelIdMetadata<C, D>
where
    D: Send + Clone + SecureDigest,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl<C: Ciphersuite, D> PartialEq for ChannelIdMetadata<C, D> {
    fn eq(&self, other: &Self) -> bool {
        self.hashed_id == other.hashed_id
    }
}

impl<C: Ciphersuite, D> Eq for ChannelIdMetadata<C, D> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::arbiter::ArbiterConfiguration;
    use crate::balance::Balances;
    use crate::cryptography::attestation::test_helpers::generate_master_keypair;
    use crate::monero::data_objects::ClosingAddresses;
    use crate::{XmrPoint, XmrScalar};
    use blake2::Blake2b;
    use ciphersuite::group::Group;
    use crate::Ed25519;
    use digest::consts::U32;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::time::Duration;

    const ALICE_ADDRESS: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const BOB_ADDRESS: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

    fn merchant_key() -> XmrPoint {
        XmrPoint::generator()
    }

    fn customer_key() -> XmrPoint {
        XmrPoint::generator() + XmrPoint::generator()
    }

    fn other_key() -> XmrPoint {
        XmrPoint::generator() * XmrScalar::random(&mut rand_core::OsRng)
    }

    /// The arbiter the two parties agreed on. Deterministic, so the known-answer vector below stays stable.
    fn test_arbiter_config() -> ArbiterConfiguration {
        let (_, big_z) = generate_master_keypair(&mut ChaCha20Rng::seed_from_u64(1));
        ArbiterConfiguration::new_with_defaults(big_z, "rdmx6-jaaaa-aaaaa-aaadq-cai")
    }

    /// A stand-in for a funding output's linking tag `L_j`.
    fn linking_tag() -> XmrPoint {
        XmrPoint::generator() * XmrScalar::from(3u64)
    }

    /// The single-output funding set the vectors below are stated over.
    fn linking_tags() -> Vec<XmrPoint> {
        vec![linking_tag()]
    }

    /// A second tag, for the dual-funded cases. Distinct from [`linking_tag`] and from [`other_key`].
    fn second_linking_tag() -> XmrPoint {
        XmrPoint::generator() * XmrScalar::from(5u64)
    }

    fn balances() -> Balances {
        Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap())
    }

    fn closing() -> ClosingAddresses {
        ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses")
    }

    /// Build the v2 metadata used by the known-answer vector below.
    fn vector_metadata() -> ChannelIdMetadata<Ed25519> {
        ChannelIdMetadata::new(merchant_key(), customer_key(), balances(), closing(), test_arbiter_config(), 100, 200)
    }

    #[test]
    fn channel_id() {
        let balance = balances();
        let closing = closing();
        let id: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), balance, closing, test_arbiter_config(), 100, 200);
        assert_eq!(id.merchant_key(), &merchant_key());
        assert_eq!(id.customer_key(), &customer_key());
        assert_eq!(id.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(id.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(id.merchant_nonce(), 100);
        assert_eq!(id.customer_nonce(), 200);
        assert_eq!(id.closing_addresses().customer().to_string(), ALICE_ADDRESS);
        assert_eq!(id.closing_addresses().merchant().to_string(), BOB_ADDRESS);
        assert_eq!(id.hash().len(), 64);
        assert_eq!(id.as_hex().len(), 65);
        assert!(id.as_hex().starts_with("XGT"), "an unfinalized id carries the provisional prefix");
        assert!(!id.is_finalized());
        assert_eq!(id.linking_tags(), None);
    }

    #[test]
    fn id_equality() {
        let amt = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let amt2 = Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.5").unwrap());
        let closing1 = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let closing2 = ClosingAddresses::new(BOB_ADDRESS, ALICE_ADDRESS).expect("should be valid closing addresses");
        let arbiter = test_arbiter_config();

        // Same parameters -> same ID
        let id1: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, arbiter.clone(), 100, 200);
        let id2: ChannelIdMetadata<Ed25519> =
            ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, arbiter.clone(), 100, 200);
        assert_eq!(id1, id2);

        // Different merchant key -> different ID
        let id3 = ChannelIdMetadata::new(other_key(), customer_key(), amt, closing1, arbiter.clone(), 100, 200);
        assert_ne!(id1, id3);

        // Different customer key -> different ID
        let id4 = ChannelIdMetadata::new(merchant_key(), other_key(), amt, closing1, arbiter.clone(), 100, 200);
        assert_ne!(id1, id4);

        // Different balance -> different ID
        let id5 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt2, closing1, arbiter.clone(), 100, 200);
        assert_ne!(id1, id5);

        // Different nonce -> different ID
        let id6 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, arbiter.clone(), 999, 200);
        assert_ne!(id1, id6);

        // Different output size -> different ID
        let id7 = ChannelIdMetadata::<Ed25519, Blake2b<U32>>::new(
            merchant_key(),
            customer_key(),
            amt,
            closing1,
            arbiter.clone(),
            100,
            200,
        );
        assert_ne!(id1.as_hex(), id7.as_hex());

        // Different closing addresses -> different ID
        let id8 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing2, arbiter.clone(), 100, 200);
        assert_ne!(id1, id8);

        // Different arbiter -> SAME ID. The arbiter is agreed between the parties but deliberately not
        // committed to by the channel id. Every field of the configuration is varied here: master key,
        // canister id and dispute window.
        let (_, other_z) = generate_master_keypair(&mut ChaCha20Rng::seed_from_u64(2));
        let other_arbiter = ArbiterConfiguration::new(other_z, "aaaaa-aa", Duration::from_secs(1234));
        let id9 = ChannelIdMetadata::new(merchant_key(), customer_key(), amt, closing1, other_arbiter, 100, 200);
        assert_eq!(id1, id9);
    }

    #[test]
    fn provisional_id_differs_from_final_id() {
        let provisional = vector_metadata();
        let provisional_id = provisional.name();
        assert!(!provisional.is_finalized());

        let mut finalized = vector_metadata();
        let final_id = finalized.finalize(linking_tags()).expect("a provisional id can be finalized");

        assert!(finalized.is_finalized());
        assert_eq!(finalized.linking_tags(), Some(&linking_tags()[..]));
        assert_ne!(provisional_id, final_id);
        // Finalizing updates the metadata in place, so the returned id is the metadata's id.
        assert_eq!(finalized.name(), final_id);
        assert!(final_id.as_str().starts_with(ChannelId::PREFIX_FINAL));
        assert_eq!(final_id.as_str().len(), ChannelId::LENGTH);
    }

    #[test]
    fn the_prefix_tracks_finalization() {
        let mut metadata = vector_metadata();

        let provisional_id = metadata.name();
        assert!(provisional_id.as_str().starts_with(ChannelId::PREFIX_PROVISIONAL));
        assert!(!provisional_id.is_finalized());
        assert_eq!(provisional_id.as_str().len(), ChannelId::LENGTH);

        let final_id = metadata.finalize(linking_tags()).unwrap();
        assert!(final_id.as_str().starts_with(ChannelId::PREFIX_FINAL));
        assert!(final_id.is_finalized());
        assert_eq!(final_id.as_str().len(), ChannelId::LENGTH);

        // The hex halves differ on their own: the prefix is a legibility tag, not the thing that separates
        // a provisional id from a final one.
        assert_ne!(provisional_id.as_str()[3..], final_id.as_str()[3..]);
    }

    /// K-20 finding F5: with respect to `compute_hash` the prefix is display-layer only, but every downstream
    /// transcript absorbs the id as its *prefixed* string, so the prefix alone domain-separates a provisional
    /// statement from a final one at the same update count. The two ids here share all 62 hex digits and differ
    /// only in prefix — the assertions hold *only* because the prefix enters each transcript, so a change that
    /// normalises ids to their hex half (or the raw hash bytes) before signing or sealing fails here.
    #[test]
    fn the_prefix_domain_separates_every_downstream_transcript() {
        use crate::arbiter::client::statement_for;
        use crate::grease_protocol::adapter_signature::adapter_signature_message;
        use crate::grease_protocol::update_record::{update_record_message, CloseHash, CLOSE_HASH_LEN, UPDATE_RECORD_DST};

        let hex = "4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let final_id = ChannelId::from_str(&format!("XGC{hex}")).unwrap();
        let provisional_id = ChannelId::from_str(&format!("XGT{hex}")).unwrap();
        let update_count = 7;
        let close_hash = CloseHash::new([0xaa; CLOSE_HASH_LEN]);

        // The dispute statement absorbs the id string whole, prefix included. Its encoding is frozen as
        // `u32-LE(len) ‖ channel_id ‖ u64-LE(update_count)`, so the prefix sits at bytes 4..7 of `m` — and a
        // provisional id yields no statement at all, the strongest form of non-collision.
        let final_m = statement_for(&final_id, update_count).expect("a final id forms a statement").to_bytes();
        assert_eq!(&final_m[4..4 + ChannelId::LENGTH], final_id.as_str().as_bytes());
        statement_for(&provisional_id, update_count).expect_err("a provisional id must be refused a statement");

        // The update-record message likewise carries the prefixed id whole, at its frozen offset.
        let final_rec = update_record_message(&final_id, update_count, &close_hash);
        let provisional_rec = update_record_message(&provisional_id, update_count, &close_hash);
        let id_at = 8 + UPDATE_RECORD_DST.len() + 4;
        assert_eq!(&final_rec[id_at..id_at + ChannelId::LENGTH], final_id.as_str().as_bytes());
        assert_eq!(&provisional_rec[id_at..id_at + ChannelId::LENGTH], provisional_id.as_str().as_bytes());
        assert_ne!(final_rec, provisional_rec, "provisional and final record messages must not collide at the same count");
        assert_eq!(final_rec[..id_at], provisional_rec[..id_at]);
        assert_eq!(final_rec[id_at + 3..], provisional_rec[id_at + 3..]);

        // The adapter-signature message absorbs the same prefixed string, and a provisional id is refused a
        // message outright — so the two ids cannot collide at the same (count, close hash) here either.
        adapter_signature_message(&final_id, update_count, &close_hash).expect("a final id forms a message");
        adapter_signature_message(&provisional_id, update_count, &close_hash)
            .expect_err("a provisional id must be refused an adapter-signature message");
    }

    #[test]
    fn parsing_recovers_the_kind_from_the_prefix() {
        let hex = "4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";

        let final_id = ChannelId::from_str(&format!("XGC{hex}")).expect("XGC is a valid prefix");
        assert!(final_id.is_finalized());

        let provisional_id = ChannelId::from_str(&format!("XGT{hex}")).expect("XGT is a valid prefix");
        assert!(!provisional_id.is_finalized());
        assert_eq!(provisional_id.as_str(), format!("XGT{hex}"));

        // Any other prefix is rejected, even at the right length with valid hex.
        assert_eq!(ChannelId::from_str(&format!("XGX{hex}")), Err(ChannelIdParseError::InvalidPrefix));
    }

    /// K-20 finding F8: storage keys channel state by the provisional id, so that key must be recoverable,
    /// unchanged, from finalized metadata — otherwise the record under it is orphaned the moment the current
    /// id flips to `XGC…`.
    #[test]
    fn the_provisional_name_is_invariant_under_finalization() {
        let mut metadata = vector_metadata();
        let provisional_id = metadata.name();
        assert_eq!(metadata.provisional_name(), provisional_id, "before finalization the two names coincide");

        let final_id = metadata.finalize(linking_tags()).unwrap();
        assert_eq!(metadata.provisional_name(), provisional_id, "finalization must not move the provisional name");
        assert_ne!(metadata.provisional_name(), final_id, "the current id has absorbed L_F and differs in its hex half");
        assert!(!metadata.provisional_name().is_finalized());
        assert_eq!(metadata.name(), final_id, "the current id is untouched by recomputing the provisional one");
    }

    #[test]
    fn a_finalized_id_cannot_be_rebound() {
        let mut id = vector_metadata();
        let final_id = id.finalize(linking_tags()).unwrap();

        // Re-binding, whether to a different funding output or to the same one, is rejected: it would
        // silently rename a channel that peers and stored records already refer to by `final_id`.
        assert_eq!(id.finalize(vec![other_key()]), Err(ChannelIdFinalizeError::AlreadyFinalized));
        assert_eq!(id.finalize(linking_tags()), Err(ChannelIdFinalizeError::AlreadyFinalized));

        // The rejected calls left the id untouched.
        assert_eq!(id.name(), final_id);
        assert_eq!(id.linking_tags(), Some(&linking_tags()[..]));
    }

    /// A curve-generic backstop under the contribution proof: the identity is the one linking tag two channels
    /// could be forced to share without anyone knowing a secret, since it is the sum of any partial and its
    /// negation. Refusing it leaves the id provisional, so the exchange can be retried.
    #[test]
    fn an_identity_linking_tag_is_refused() {
        let mut id = vector_metadata();
        let provisional = id.name();

        assert_eq!(id.finalize(vec![XmrPoint::identity()]), Err(ChannelIdFinalizeError::DegenerateLinkingTag));

        assert!(!id.is_finalized());
        assert_eq!(id.name(), provisional, "a refused tag must leave the id untouched");
        assert!(id.finalize(linking_tags()).is_ok(), "and must not block a later, valid tag");
    }

    #[test]
    fn final_id_commits_to_the_linking_tag() {
        let mut a = vector_metadata();
        let mut b = vector_metadata();
        assert_eq!(a.name(), b.name(), "identical parameters must give identical provisional ids");

        let id_a = a.finalize(linking_tags()).unwrap();
        let id_b = b.finalize(vec![other_key()]).unwrap();
        assert_ne!(id_a, id_b, "a different funding output must give a different channel id");
    }

    #[test]
    fn nonces_blind_the_linking_tag() {
        // Two channels over the same funding output but with different nonces must be unlinkable by id,
        // i.e. the id hides its linking tags.
        let mut a = ChannelIdMetadata::<Ed25519>::new(
            merchant_key(),
            customer_key(),
            balances(),
            closing(),
            test_arbiter_config(),
            100,
            200,
        );
        let mut b = ChannelIdMetadata::<Ed25519>::new(
            merchant_key(),
            customer_key(),
            balances(),
            closing(),
            test_arbiter_config(),
            101,
            200,
        );
        let mut c = ChannelIdMetadata::<Ed25519>::new(
            merchant_key(),
            customer_key(),
            balances(),
            closing(),
            test_arbiter_config(),
            100,
            201,
        );

        let id_a = a.finalize(linking_tags()).unwrap();
        let id_b = b.finalize(linking_tags()).unwrap();
        let id_c = c.finalize(linking_tags()).unwrap();

        assert_ne!(id_a, id_b, "a different merchant nonce must give a different id");
        assert_ne!(id_a, id_c, "a different customer nonce must give a different id");
    }

    /// Either party's nonce, alone, separates two otherwise identical channels — already at the provisional
    /// stage, before any funding output exists. This is what keeps id uniqueness from resting solely on
    /// spend-key freshness: a party that draws its nonce fresh is protected from an id collision
    /// unilaterally, whatever the counterparty reuses.
    #[test]
    fn either_partys_nonce_alone_separates_provisional_ids() {
        let base = |merchant_nonce, customer_nonce| {
            ChannelIdMetadata::<Ed25519>::new(
                merchant_key(),
                customer_key(),
                balances(),
                closing(),
                test_arbiter_config(),
                merchant_nonce,
                customer_nonce,
            )
        };

        let id = base(100, 200).name();
        assert_ne!(id, base(101, 200).name(), "the merchant's nonce alone must separate provisional ids");
        assert_ne!(id, base(100, 201).name(), "the customer's nonce alone must separate provisional ids");
        // The residual the nonces cannot remove: if *both* parties repeat their nonces (and every other
        // field), the ids collide. That risk sits with the parties that reused.
        assert_eq!(id, base(100, 200).name());
    }

    /// Recompute the v2 transcript hash byte by byte, independently of `DigestTranscript`, and check the
    /// frozen vector against it. `DigestTranscript` prefixes every write with a member tag byte and the
    /// value's length as a little-endian u64; `challenge` appends the challenge label the same way and then
    /// forks the state with a `Challenged` (6) byte.
    #[test]
    fn known_answer_vector() {
        use blake2::Digest;

        const NAME: u8 = 0;
        const LABEL: u8 = 2;
        const VALUE: u8 = 3;
        const CHALLENGE: u8 = 4;
        const CHALLENGED: u8 = 6;

        let mut hasher = Blake2b512::new();
        let mut absorb = |kind: u8, bytes: &[u8]| {
            hasher.update([kind]);
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        absorb(NAME, b"Grease ChannelId v2");

        let fields: [(&[u8], Vec<u8>); 9] = [
            (b"merchant_key", merchant_key().to_bytes().to_vec()),
            (b"customer_key", customer_key().to_bytes().to_vec()),
            (b"merchant_balance", 1_250_000_000_000u64.to_le_bytes().to_vec()),
            (b"customer_balance", 750_000_000_000u64.to_le_bytes().to_vec()),
            (b"merchant_closing_address", BOB_ADDRESS.as_bytes().to_vec()),
            (b"customer_closing_address", ALICE_ADDRESS.as_bytes().to_vec()),
            (b"funding_linking_tags", linking_tag().to_bytes().to_vec()),
            (b"merchant_nonce", 100u64.to_le_bytes().to_vec()),
            (b"customer_nonce", 200u64.to_le_bytes().to_vec()),
        ];
        fields.iter().for_each(|(label, value)| {
            absorb(LABEL, label);
            absorb(VALUE, value);
        });
        absorb(CHALLENGE, b"channel_id");
        hasher.update([CHALLENGED]);
        let expected = hasher.finalize();

        let mut metadata = vector_metadata();
        let id = metadata.finalize(linking_tags()).unwrap();
        assert_eq!(metadata.hash(), &expected[..], "transcript encoding drifted from the v2 specification");

        // Frozen so that a change to any part of the derivation fails loudly. The value is not taken on
        // trust: the assertion above derives the same hash from a hand-written encoding of the transcript,
        // so this literal only restates its first 31 bytes in the human-readable form.
        assert_eq!(id.as_str(), "XGC78141ecb5daa678fd52ee334cb654ca7d76c425329615570020fa90668f590");
        assert_eq!(id.as_str()[3..], hex::encode(&expected[..31]));
    }

    /// The tags are absorbed as one length-prefixed transcript message, so a channel funded by one output and
    /// a channel funded by two can never share an id through their concatenation.
    ///
    /// The dual-funded channel's value *begins* with the singly-funded channel's, so under an unprefixed
    /// encoding the two would be distinguished only by whatever followed. `DigestTranscript` writes the value's
    /// length before the value, which is the property that makes the two hashes differ; a change that dropped
    /// the length prefix fails here.
    #[test]
    fn one_tag_cannot_collide_with_two() {
        let mut single = vector_metadata();
        let mut dual = vector_metadata();
        let (a, b) = (linking_tag(), second_linking_tag());

        let single_id = single.finalize(vec![a]).unwrap();
        let dual_id = dual.finalize(vec![a, b]).unwrap();
        assert_ne!(single_id, dual_id, "a singly-funded id must not collide with a dual-funded one");

        // The prefix property the assertion rests on: one value is a prefix of the other.
        let concat = |tags: &[XmrPoint]| tags.iter().flat_map(|t| t.to_bytes().to_vec()).collect::<Vec<u8>>();
        let mut sorted = [a, b];
        sorted.sort_unstable_by(|x, y| x.to_bytes().cmp(&y.to_bytes()));
        assert_eq!(concat(&sorted[..1]), concat(&sorted)[..32].to_vec());
        assert_eq!(concat(&sorted).len(), 64);

        // And the other single tag agrees with neither.
        let mut other = vector_metadata();
        let other_id = other.finalize(vec![b]).unwrap();
        assert_ne!(other_id, single_id);
        assert_ne!(other_id, dual_id);
    }

    /// Declaration order must not reach the id: the tags are sorted before they are absorbed, so it makes no
    /// difference which party declared first.
    #[test]
    fn tags_are_absorbed_in_ascending_order() {
        let (a, b) = (linking_tag(), second_linking_tag());
        let mut forwards = vector_metadata();
        let mut backwards = vector_metadata();

        let id_forwards = forwards.finalize(vec![a, b]).unwrap();
        let id_backwards = backwards.finalize(vec![b, a]).unwrap();
        assert_eq!(id_forwards, id_backwards, "declaration order must not change the channel id");

        // Both are stored ascending by encoding, whichever order they arrived in.
        let stored = forwards.linking_tags().expect("the id is final").to_vec();
        assert_eq!(stored, backwards.linking_tags().expect("the id is final").to_vec());
        assert!(stored.windows(2).all(|p| p[0].to_bytes() <= p[1].to_bytes()), "tags must be stored ascending");
        // At least one of the two orders was reordered on the way in, so the sort is doing work.
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert!(stored[0].to_bytes() < stored[1].to_bytes());
    }

    /// Two equal tags mean the two funders declared the same output. No honest channel produces that, and
    /// absorbing it would let a dual-funded channel present one output twice.
    #[test]
    fn a_duplicate_funding_tag_is_refused() {
        let mut id = vector_metadata();
        let provisional = id.name();

        assert_eq!(id.finalize(vec![linking_tag(), linking_tag()]), Err(ChannelIdFinalizeError::DuplicateLinkingTag));
        assert!(!id.is_finalized());
        assert_eq!(id.name(), provisional, "a refused set must leave the id untouched");

        // A duplicate anywhere in the set is caught, not only an adjacent pair as declared.
        let mut id = vector_metadata();
        let tags = vec![linking_tag(), second_linking_tag(), linking_tag()];
        assert_eq!(id.finalize(tags), Err(ChannelIdFinalizeError::DuplicateLinkingTag));

        // And a distinct pair still binds.
        assert!(id.finalize(vec![linking_tag(), second_linking_tag()]).is_ok());
    }

    /// A channel is funded by at least one output, so an empty tag set is not a final id — it is the
    /// provisional transcript wearing the final prefix.
    #[test]
    fn an_empty_tag_set_is_refused() {
        let mut id = vector_metadata();
        let provisional = id.name();
        assert_eq!(id.finalize(Vec::new()), Err(ChannelIdFinalizeError::NoLinkingTags));
        assert!(!id.is_finalized());
        assert_eq!(id.name(), provisional);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut id: ChannelIdMetadata<Ed25519> = ChannelIdMetadata::new(
            merchant_key(),
            customer_key(),
            balances(),
            closing(),
            test_arbiter_config(),
            12345,
            67890,
        );

        // A provisional id round-trips with no linking tag at all.
        let provisional: ChannelIdMetadata<Ed25519> = ron::from_str(&ron::to_string(&id).unwrap()).unwrap();
        assert!(!provisional.is_finalized());
        assert_eq!(provisional.name(), id.name());

        // A dual-funded channel, so the round trip exercises the sequence encoding rather than a lone element.
        id.finalize(vec![linking_tag(), second_linking_tag()]).unwrap();
        let serialized = ron::to_string(&id).unwrap();
        let deserialized: ChannelIdMetadata<Ed25519> = ron::from_str(&serialized).unwrap();

        assert_eq!(id.merchant_key(), deserialized.merchant_key());
        assert_eq!(id.customer_key(), deserialized.customer_key());
        assert_eq!(id.initial_balance(), deserialized.initial_balance());
        assert_eq!(id.merchant_nonce(), deserialized.merchant_nonce());
        assert_eq!(id.customer_nonce(), deserialized.customer_nonce());
        assert_eq!(id.hash(), deserialized.hash());
        assert_eq!(id.linking_tags(), deserialized.linking_tags());
        assert!(deserialized.is_finalized());
        assert_eq!(
            id.closing_addresses().merchant().to_string(),
            deserialized.closing_addresses().merchant().to_string()
        );
        assert_eq!(
            id.closing_addresses().customer().to_string(),
            deserialized.closing_addresses().customer().to_string()
        );
    }

    #[test]
    fn channel_id_string_from_channel_id() {
        let id = vector_metadata();
        let id_string = ChannelId::from_channel_id_metadata(&id);
        // `vector_metadata` is provisional, so the id carries the temporary prefix.
        assert!(id_string.as_str().starts_with("XGT"));
        assert!(!id_string.is_finalized());
        assert_eq!(id_string.as_str().len(), 65);
    }

    #[test]
    fn channel_id_string_from_str() {
        // Valid channel ID
        let valid = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let id = ChannelId::from_str(valid).unwrap();
        assert_eq!(id.as_str(), valid);

        // Invalid: wrong length
        let too_short = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a38";
        assert!(matches!(
            ChannelId::from_str(too_short),
            Err(ChannelIdParseError::InvalidLength(64))
        ));

        // Invalid: wrong prefix
        let wrong_prefix = "ABC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        assert!(matches!(
            ChannelId::from_str(wrong_prefix),
            Err(ChannelIdParseError::InvalidPrefix)
        ));

        // Invalid: non-hex characters - 'z' is not valid hex (62 z's after XGC = 65 chars total)
        let invalid_hex = "XGCzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert_eq!(invalid_hex.len(), 65, "Test setup error: invalid_hex should be 65 chars");
        assert!(matches!(ChannelId::from_str(invalid_hex), Err(ChannelIdParseError::InvalidHex)));
    }

    #[test]
    fn channel_id_string_display() {
        let valid = "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383";
        let id = ChannelId::from_str(valid).unwrap();
        assert_eq!(format!("{id}"), valid);
        assert_eq!(format!("{id:?}"), format!("ChannelId({valid})"));
    }

    #[test]
    fn channel_id_string_equality_and_hash() {
        use std::collections::HashSet;

        let a = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
        let b = ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();
        // Different ID - 62 zeros after XGC = 65 chars total
        let c = ChannelId::from_str("XGC00000000000000000000000000000000000000000000000000000000000000").unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);

        // Test hash works correctly
        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn channel_id_string_serialize_deserialize() {
        let original =
            ChannelId::from_str("XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383").unwrap();

        let serialized = ron::to_string(&original).unwrap();
        let deserialized: ChannelId = ron::from_str(&serialized).unwrap();

        assert_eq!(original, deserialized);
    }
}
