use crate::state_machine::Balances;
use digest::Digest;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};

#[derive(Clone, Serialize, Deserialize)]
pub struct ChannelId {
    merchant_id: String,
    customer_id: String,
    initial_balance: Balances,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    salt: Vec<u8>,
    #[serde(serialize_with = "crate::helpers::to_hex", deserialize_with = "crate::helpers::from_hex")]
    hashed_id: Vec<u8>,
}

impl ChannelId {
    pub fn new<D, S1, S2, S3>(merchant: S1, customer: S2, salt: S3, initial_balance: Balances) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: AsRef<[u8]>,
        D: Digest,
    {
        let merchant_id = merchant.into();
        let customer_id = customer.into();
        let salt = salt.as_ref().to_vec();
        let amount_mer = initial_balance.merchant.to_piconero().to_le_bytes();
        let amount_cust = initial_balance.customer.to_piconero().to_le_bytes();
        let mut hasher = D::new();
        hasher.update(b"ChannelId");
        hasher.update(&merchant_id);
        hasher.update(&customer_id);
        hasher.update(amount_mer);
        hasher.update(amount_cust);
        hasher.update(&salt);
        let hashed_id = hasher.finalize().to_vec();
        ChannelId { merchant_id, customer_id, initial_balance, salt, hashed_id }
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
            .field("salt", &hex::encode(&self.salt))
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
    use crate::channel_id::ChannelId;
    use crate::state_machine::Balances;
    use blake2::Blake2b;
    use digest::consts::{U16, U32};

    #[test]
    fn channel_id() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let id = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", balance);
        assert_eq!(id.merchant(), "merchant");
        assert_eq!(id.customer(), "customer");
        assert_eq!(id.initial_balance().merchant.to_piconero(), 1_250_000_000_000);
        assert_eq!(id.initial_balance().customer.to_piconero(), 750_000_000_000);
        assert_eq!(id.to_string(), "XGCa2edd1f8091cc375b12357b427a748ba");
    }

    #[test]
    fn id_equality() {
        let amt = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let amt2 = Balances::new(MoneroAmount::from_xmr("0.0").unwrap(), MoneroAmount::from_xmr("0.5").unwrap());
        let id1 = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amt);
        let id2 = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amt);
        let id4 = ChannelId::new::<Blake2b<U16>, _, _, _>("Bob", "customer", "test", amt);
        let id5 = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "Charlie", "test", amt);
        let id6 = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "Charlie", "test", amt2);
        let id7 = ChannelId::new::<Blake2b<U32>, _, _, _>("merchant", "customer", "test", amt);
        let id8 = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "customer", "xxxx", amt);
        assert_eq!(id1, id2);
        assert_ne!(id1, id4);
        assert_ne!(id1, id5);
        assert_ne!(id1, id6);
        assert_ne!(id1, id7);
        assert_ne!(id1, id8);
    }

    const SERIALIZED_CHANNEL_ID: &str = r#"(merchant_id:"merchant",customer_id:"customer",initial_balance:(merchant:1250000000000,customer:750000000000),salt:"74657374",hashed_id:"a2edd1f8091cc375b12357b427a748ba")"#;
    #[test]
    fn serialize() {
        let balance = Balances::new(MoneroAmount::from_xmr("1.25").unwrap(), MoneroAmount::from_xmr("0.75").unwrap());
        let id = ChannelId::new::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", balance);
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
        assert_eq!(deserialized.salt, b"test".to_vec());
        assert_eq!(deserialized.hashed_id, hex::decode("a2edd1f8091cc375b12357b427a748ba").unwrap());
    }
}
