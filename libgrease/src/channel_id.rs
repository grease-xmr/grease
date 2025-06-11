use crate::balance::Balances;
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelId {
    merchant_id: String,
    customer_id: String,
    initial_balance: Balances,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    hashed_id: Vec<u8>,
}

impl ChannelId {
    pub fn new<D: Digest>(merchant: impl Into<String>, customer: impl Into<String>, initial_balance: Balances) -> Self {
        let merchant_id = merchant.into();
        let customer_id = customer.into();
        let amount_mer = initial_balance.merchant.to_piconero().to_le_bytes();
        let amount_cust = initial_balance.customer.to_piconero().to_le_bytes();
        let mut hasher = D::new();
        hasher.update(b"ChannelId");
        hasher.update(&merchant_id);
        hasher.update(&customer_id);
        hasher.update(amount_mer);
        hasher.update(amount_cust);
        let hashed_id = hasher.finalize().to_vec();
        ChannelId { merchant_id, customer_id, initial_balance, hashed_id }
    }

    pub fn merchant(&self) -> &str {
        &self.merchant_id
    }

    pub fn customer(&self) -> &str {
        &self.customer_id
    }

    pub fn initial_balance(&self) -> Balances {
        self.initial_balance
    }

    pub fn hash(&self) -> &[u8] {
        &self.hashed_id
    }

    /// The channel name, which is always in the format `XGC<first 16 bytes of hex encoded channel id>`
    pub fn name(&self) -> String {
        let hash = self.hash();
        format!("XGC{}", hex::encode(&hash[..16]))
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelId")
            .field("merchant_id", &self.merchant())
            .field("customer_id", &self.customer())
            .field("initial balance (merchant)", &self.initial_balance.merchant)
            .field("initial balance (customer)", &self.initial_balance.customer)
            .field("hashed_id", &hex::encode(&self.hashed_id))
            .finish()
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
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
    use crate::amount::MoneroAmount;
    use crate::balance::Balances;
    use crate::channel_id::ChannelId;
    use blake2::Blake2b;
    use digest::consts::{U16, U32};

    #[test]
    fn channel_id() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let id = ChannelId::new::<Blake2b<U16>>("merchant", "customer", balance);
        assert_eq!(id.merchant(), "merchant");
        assert_eq!(id.customer(), "customer");
        assert_eq!(id.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(id.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(id.to_string(), "XGC056da7eb64c5a7fe3ee60a64f6d828c3");
    }

    #[test]
    fn id_equality() {
        let amt = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let amt2 = Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.5").unwrap());
        let id1 = ChannelId::new::<Blake2b<U16>>("merchant", "customer", amt);
        let id2 = ChannelId::new::<Blake2b<U16>>("merchant", "customer", amt);
        let id4 = ChannelId::new::<Blake2b<U16>>("Bob", "customer", amt);
        let id5 = ChannelId::new::<Blake2b<U16>>("merchant", "Charlie", amt);
        let id6 = ChannelId::new::<Blake2b<U16>>("merchant", "Charlie", amt2);
        let id7 = ChannelId::new::<Blake2b<U32>>("merchant", "customer", amt);
        assert_eq!(id1, id2);
        assert_ne!(id1, id4);
        assert_ne!(id1, id5);
        assert_ne!(id1, id6);
        assert_ne!(id1, id7);
    }

    const SERIALIZED_CHANNEL_ID: &str = r#"(merchant_id:"merchant",customer_id:"customer",initial_balance:(merchant:1250000000000,customer:750000000000),hashed_id:"056da7eb64c5a7fe3ee60a64f6d828c3")"#;
    #[test]
    fn serialize() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let id = ChannelId::new::<Blake2b<U16>>("merchant", "customer", balance);
        let serialized = ron::to_string(&id).unwrap();
        assert_eq!(serialized, SERIALIZED_CHANNEL_ID);
    }

    #[test]
    fn deserialize() {
        let deserialized: ChannelId = ron::from_str(SERIALIZED_CHANNEL_ID).unwrap();
        assert_eq!(deserialized.merchant(), "merchant");
        assert_eq!(deserialized.customer(), "customer");
        assert_eq!(deserialized.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(deserialized.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(deserialized.hashed_id, hex::decode("056da7eb64c5a7fe3ee60a64f6d828c3").unwrap());
    }
}
