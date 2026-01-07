use crate::balance::Balances;
use crate::cryptography::keys::Curve25519PublicKey;
use crate::monero::data_objects::ClosingAddresses;
use blake2::Blake2b512;
use digest::consts::U32;
use digest::typenum::{IsGreaterOrEqual, True};
use digest::OutputSizeUser;
use flexible_transcript::{DigestTranscript, SecureDigest, Transcript};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::marker::PhantomData;

/// The unique identifier for a payment channel.
///
/// The channel ID is derived from a digest transcript hash (domain separator: `"Grease ChannelId v1"`)
/// over the following fields, in order:
/// - `merchant_key`: The merchant's Curve25519 public key (32 bytes, compressed)
/// - `customer_key`: The customer's Curve25519 public key (32 bytes, compressed)
/// - `merchant_balance`: The merchant's initial balance in piconero (u64, little-endian)
/// - `customer_balance`: The customer's initial balance in piconero (u64, little-endian)
/// - `merchant_closing_address`: The merchant's Monero closing address
/// - `customer_closing_address`: The customer's Monero closing address
/// - `merchant_nonce`: The merchant's channel nonce (u64, little-endian)
/// - `customer_nonce`: The customer's channel nonce (u64, little-endian)
///
/// The digest type `D` must produce at least 32 bytes of output. The default (`Blake2b512`)
/// produces a 64-byte hash. The human-readable channel ID format is `XGC` followed by the
/// first 31 bytes of the hash encoded as hex (65 characters total).
#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelId<D = Blake2b512> {
    merchant_key: Curve25519PublicKey,
    customer_key: Curve25519PublicKey,
    initial_balance: Balances,
    closing_addresses: ClosingAddresses,
    /// The merchant's contribution to the channel nonce
    merchant_nonce: u64,
    /// The customer's contribution to the channel nonce
    customer_nonce: u64,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    hashed_id: Vec<u8>,
    _phantom: PhantomData<D>,
}

impl<D> ChannelId<D>
where
    D: Send + Clone + SecureDigest,
    <D as OutputSizeUser>::OutputSize: IsGreaterOrEqual<U32, Output = True>,
{
    /// Create a new channel ID from the given parameters.
    ///
    /// See [`ChannelId`] for the full specification of the hash computation.
    ///
    /// The generic parameter `D` controls the digest algorithm and output size.
    /// The digest must produce at least 32 bytes of output (enforced at compile time).
    ///
    /// # Compile-time safety
    ///
    /// Using a digest with fewer than 32 bytes of output will fail to compile:
    ///
    /// ```compile_fail
    /// use libgrease::channel_id::ChannelId;
    /// #use libgrease::cryptography::keys::{Curve25519PublicKey, PublicKey};
    /// #use libgrease::balance::Balances;
    /// #use libgrease::monero::data_objects::ClosingAddresses;
    /// #use blake2::Blake2b;
    /// #use digest::consts::U16;
    ///
    /// // This fails to compile because Blake2b<U16> only produces 16 bytes
    /// fn wont_compile(
    ///     merchant_key: Curve25519PublicKey,
    ///     customer_key: Curve25519PublicKey,
    ///     balance: Balances,
    ///     closing: ClosingAddresses,
    /// ) {
    ///     let _ = ChannelId::<Blake2b<U16>>::new(
    ///         merchant_key, customer_key, balance, closing, 0, 0
    ///     );
    /// }
    /// ```
    pub fn new(
        merchant_key: Curve25519PublicKey,
        customer_key: Curve25519PublicKey,
        initial_balance: Balances,
        closing_addresses: ClosingAddresses,
        merchant_nonce: u64,
        customer_nonce: u64,
    ) -> Self {
        let amount_mer = initial_balance.merchant.to_piconero().to_le_bytes();
        let amount_cust = initial_balance.customer.to_piconero().to_le_bytes();

        let mut transcript = DigestTranscript::<D>::new(b"Grease ChannelId v1");
        transcript.append_message(b"merchant_key", merchant_key.to_compressed().as_bytes());
        transcript.append_message(b"customer_key", customer_key.to_compressed().as_bytes());
        transcript.append_message(b"merchant_balance", amount_mer);
        transcript.append_message(b"customer_balance", amount_cust);
        transcript.append_message(b"merchant_closing_address", closing_addresses.merchant().as_bytes());
        transcript.append_message(b"customer_closing_address", closing_addresses.customer().as_bytes());
        transcript.append_message(b"merchant_nonce", merchant_nonce.to_le_bytes());
        transcript.append_message(b"customer_nonce", customer_nonce.to_le_bytes());

        let challenge = transcript.challenge(b"channel_id");
        let output_size = <D as OutputSizeUser>::output_size();
        let hashed_id = challenge[..output_size].to_vec();

        ChannelId {
            merchant_key,
            customer_key,
            initial_balance,
            hashed_id,
            closing_addresses,
            merchant_nonce,
            customer_nonce,
            _phantom: PhantomData,
        }
    }

    pub fn merchant_key(&self) -> &Curve25519PublicKey {
        &self.merchant_key
    }

    pub fn customer_key(&self) -> &Curve25519PublicKey {
        &self.customer_key
    }

    pub fn initial_balance(&self) -> Balances {
        self.initial_balance
    }

    pub fn closing_addresses(&self) -> &ClosingAddresses {
        &self.closing_addresses
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

    /// Returns the channel ID as a hex string in the format `XGC<first 31 bytes of hash in hex>`.
    /// This produces a 65-character string: "XGC" prefix + 62 hex characters.
    pub fn as_hex(&self) -> String {
        let hash = self.hash();
        format!("XGC{}", hex::encode(&hash[..31]))
    }

    /// Alias for [`as_hex`](Self::as_hex) for backwards compatibility.
    pub fn name(&self) -> String {
        self.as_hex()
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelId")
            .field("merchant_key", &self.merchant_key.as_hex())
            .field("customer_key", &self.customer_key.as_hex())
            .field("initial balance (merchant)", &self.initial_balance.merchant)
            .field("initial balance (customer)", &self.initial_balance.customer)
            .field("merchant_nonce", &self.merchant_nonce)
            .field("customer_nonce", &self.customer_nonce)
            .field("hashed_id", &hex::encode(&self.hashed_id))
            .finish()
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex())
    }
}

impl PartialEq for ChannelId {
    fn eq(&self, other: &Self) -> bool {
        self.hashed_id == other.hashed_id
    }
}

impl Eq for ChannelId {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::amount::MoneroAmount;
    use crate::balance::Balances;
    use crate::cryptography::keys::Curve25519PublicKey;
    use crate::monero::data_objects::ClosingAddresses;
    use blake2::Blake2b;
    use digest::consts::{U32, U64};

    const ALICE_ADDRESS: &str =
        "43i4pVer2tNFELvfFEEXxmbxpwEAAFkmgN2wdBiaRNcvYcgrzJzVyJmHtnh2PWR42JPeDVjE8SnyK3kPBEjSixMsRz8TncK";
    const BOB_ADDRESS: &str =
        "4BH2vFAir1iQCwi2RxgQmsL1qXmnTR9athNhpK31DoMwJgkpFUp2NykFCo4dXJnMhU7w9UZx7uC6qbNGuePkRLYcFo4N7p3";

    // Valid Curve25519 public keys for testing (derived from known secret keys)
    const MERCHANT_KEY_HEX: &str = "4dd896d542721742aff8671ba42aff0c4c846bea79065cf39a191bbeb11ea634";
    const CUSTOMER_KEY_HEX: &str = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";

    fn merchant_key() -> Curve25519PublicKey {
        Curve25519PublicKey::from_hex(MERCHANT_KEY_HEX).unwrap()
    }

    fn customer_key() -> Curve25519PublicKey {
        Curve25519PublicKey::from_hex(CUSTOMER_KEY_HEX).unwrap()
    }

    fn other_key() -> Curve25519PublicKey {
        // Generate a different key for testing
        use crate::cryptography::keys::PublicKey;
        let (_, key) = Curve25519PublicKey::keypair(&mut rand_core::OsRng);
        key
    }

    #[test]
    fn channel_id() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let id: ChannelId = ChannelId::new(merchant_key(), customer_key(), balance, closing, 100, 200);
        assert_eq!(id.merchant_key(), &merchant_key());
        assert_eq!(id.customer_key(), &customer_key());
        assert_eq!(id.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(id.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(id.merchant_nonce(), 100);
        assert_eq!(id.customer_nonce(), 200);
        assert_eq!(id.closing_addresses().customer().to_string(), ALICE_ADDRESS);
        assert_eq!(id.closing_addresses().merchant().to_string(), BOB_ADDRESS);
        // The hash should be 64 bytes with Blake2b512
        assert_eq!(id.hash().len(), 64);
        assert_eq!(id.as_hex().len(), 65);
        assert_eq!(id.as_hex(), "XGC4a7024e7fd6f5c6a2d0131d12fd91ecd17f5da61c2970d603a05053b41a383")
    }

    #[test]
    fn id_equality() {
        let amt = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let amt2 = Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.5").unwrap());
        let closing1 = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let closing2 = ClosingAddresses::new(BOB_ADDRESS, ALICE_ADDRESS).expect("should be valid closing addresses");

        // Same parameters -> same ID
        let id1 = ChannelId::new(merchant_key(), customer_key(), amt, closing1, 100, 200);
        let id2 = ChannelId::new(merchant_key(), customer_key(), amt, closing1, 100, 200);
        assert_eq!(id1, id2);

        // Different merchant key -> different ID
        let id3 = ChannelId::new(other_key(), customer_key(), amt, closing1, 100, 200);
        assert_ne!(id1, id3);

        // Different customer key -> different ID
        let id4 = ChannelId::new(merchant_key(), other_key(), amt, closing1, 100, 200);
        assert_ne!(id1, id4);

        // Different balance -> different ID
        let id5 = ChannelId::new(merchant_key(), customer_key(), amt2, closing1, 100, 200);
        assert_ne!(id1, id5);

        // Different nonce -> different ID
        let id6 = ChannelId::new(merchant_key(), customer_key(), amt, closing1, 999, 200);
        assert_ne!(id1, id6);

        // Different output size -> different ID
        let id7 = ChannelId::<Blake2b<U32>>::new(merchant_key(), customer_key(), amt, closing1, 100, 200);
        assert_ne!(id1.as_hex(), id7.as_hex());

        // Different closing addresses -> different ID
        let id8 = ChannelId::new(merchant_key(), customer_key(), amt, closing2, 100, 200);
        assert_ne!(id1, id8);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let closing = ClosingAddresses::new(ALICE_ADDRESS, BOB_ADDRESS).expect("should be valid closing addresses");
        let id: ChannelId = ChannelId::new(merchant_key(), customer_key(), balance, closing, 12345, 67890);

        let serialized = ron::to_string(&id).unwrap();
        let deserialized: ChannelId = ron::from_str(&serialized).unwrap();

        assert_eq!(id.merchant_key(), deserialized.merchant_key());
        assert_eq!(id.customer_key(), deserialized.customer_key());
        assert_eq!(id.initial_balance(), deserialized.initial_balance());
        assert_eq!(id.merchant_nonce(), deserialized.merchant_nonce());
        assert_eq!(id.customer_nonce(), deserialized.customer_nonce());
        assert_eq!(id.hash(), deserialized.hash());
        assert_eq!(
            id.closing_addresses().merchant().to_string(),
            deserialized.closing_addresses().merchant().to_string()
        );
        assert_eq!(
            id.closing_addresses().customer().to_string(),
            deserialized.closing_addresses().customer().to_string()
        );
    }
}
