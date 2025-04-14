use crate::amount::MoneroAmount;
use chrono::{DateTime, Utc};
use digest::Digest;
use std::fmt::{Debug, Display};

#[derive(Clone)]
pub struct ChannelId {
    merchant_id: Vec<u8>,
    customer_id: Vec<u8>,
    amount: MoneroAmount,
    salt: Vec<u8>,
    timestamp: DateTime<Utc>,
    hashed_id: Vec<u8>,
}

impl ChannelId {
    pub fn new<D, S1, S2, S3>(merchant: S1, customer: S2, salt: S3, amount: MoneroAmount) -> Self
    where
        S1: AsRef<[u8]>,
        S2: AsRef<[u8]>,
        S3: AsRef<[u8]>,
        D: Digest,
    {
        ChannelId::new_with_timestamp::<D, S1, S2, S3>(merchant, customer, salt, amount, Utc::now())
    }

    pub fn new_with_timestamp<D, S1, S2, S3>(
        merchant: S1,
        customer: S2,
        salt: S3,
        amount: MoneroAmount,
        timestamp: DateTime<Utc>,
    ) -> Self
    where
        S1: AsRef<[u8]>,
        S2: AsRef<[u8]>,
        S3: AsRef<[u8]>,
        D: Digest,
    {
        let merchant_id = merchant.as_ref().to_vec();
        let customer_id = customer.as_ref().to_vec();
        let salt = salt.as_ref().to_vec();
        let amount_val = amount.to_piconero().to_le_bytes();
        let timestamp_val = timestamp.timestamp_micros().to_le_bytes();
        let mut hasher = D::new();
        hasher.update(b"ChannelId");
        hasher.update(&merchant_id);
        hasher.update(&customer_id);
        hasher.update(&amount_val);
        hasher.update(&timestamp_val);
        hasher.update(&salt);
        let hashed_id = hasher.finalize().to_vec();
        ChannelId { merchant_id, customer_id, amount, salt, timestamp, hashed_id }
    }

    pub fn merchant(&self) -> String {
        String::from_utf8(self.merchant_id.clone()).unwrap_or_else(|_| "Merchant".to_string())
    }

    pub fn customer(&self) -> String {
        String::from_utf8(self.customer_id.clone()).unwrap_or_else(|_| "Merchant".to_string())
    }

    pub fn amount(&self) -> &MoneroAmount {
        &self.amount
    }

    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelId")
            .field("merchant_id", &self.merchant())
            .field("customer_id", &self.customer())
            .field("salt", &hex::encode(&self.salt))
            .field("amount", &self.amount)
            .field("timestamp", &self.timestamp)
            .field("hashed_id", &hex::encode(&self.hashed_id))
            .finish()
    }
}

impl Display for ChannelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.hashed_id))
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
    use blake2::Blake2b;
    use chrono::{TimeZone, Utc};
    use digest::consts::{U16, U32};

    #[test]
    fn channel_id() {
        let ts = Utc.with_ymd_and_hms(2024, 11, 12, 0, 0, 0).unwrap();
        let amount = MoneroAmount::from_xmr("1.25").unwrap();
        let id = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amount, ts);
        assert_eq!(id.merchant(), "merchant");
        assert_eq!(id.customer(), "customer");
        assert_eq!(id.amount().to_piconero(), 1_250_000_000_000);
        assert_eq!(id.to_string(), "b736f9afc13a20c179453cfcc339e06c");
    }

    #[test]
    fn id_equality() {
        let ts = Utc.with_ymd_and_hms(2024, 11, 12, 0, 0, 0).unwrap();
        let amount = MoneroAmount::from_xmr("1.25").unwrap();
        let amt2 = MoneroAmount::from_xmr("1.5").unwrap();
        let id1 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amount, ts);
        let id2 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amount, ts);
        let id3 =
            ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "customer", "test", amount, Utc::now());
        let id4 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("Bob", "customer", "test", amount, ts);
        let id5 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "Charlie", "test", amount, ts);
        let id6 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "Charlie", "test", amt2, ts);
        let id7 = ChannelId::new_with_timestamp::<Blake2b<U32>, _, _, _>("merchant", "customer", "test", amount, ts);
        let id8 = ChannelId::new_with_timestamp::<Blake2b<U16>, _, _, _>("merchant", "customer", "xxxx", amount, ts);
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
        assert_ne!(id1, id5);
        assert_ne!(id1, id6);
        assert_ne!(id1, id7);
        assert_ne!(id1, id8);
    }
}
