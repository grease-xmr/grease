mod error;
pub mod multisig_keyring;
pub mod multisig_negotiation;

use crate::error::ReadError;
pub use error::UpdateError;
use modular_frost::sign::Writable;
use monero::consensus::{ReadExt, WriteExt};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::io::{Read, Write};

/// Trait for types that have an associated channel role (Merchant or Customer)
pub trait HasRole {
    /// Returns the channel role associated with the implementing type
    fn role(&self) -> ChannelRole;

    fn is_other_role(&self, other: &ChannelRole) -> bool {
        self.role() != *other
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelRole {
    Merchant,
    Customer,
}

impl Display for ChannelRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelRole::Merchant => write!(f, "Merchant"),
            ChannelRole::Customer => write!(f, "Customer"),
        }
    }
}

impl ChannelRole {
    pub const fn other(&self) -> Self {
        match self {
            ChannelRole::Merchant => ChannelRole::Customer,
            ChannelRole::Customer => ChannelRole::Merchant,
        }
    }

    pub const fn is_merchant(&self) -> bool {
        matches!(self, ChannelRole::Merchant)
    }

    pub const fn is_customer(&self) -> bool {
        matches!(self, ChannelRole::Customer)
    }

    pub const fn as_u8(&self) -> u8 {
        match self {
            ChannelRole::Merchant => 0,
            ChannelRole::Customer => 1,
        }
    }

    pub fn read<R: Read + ?Sized>(reader: &mut R) -> Result<Self, ReadError> {
        let v = reader.read_u8().map_err(|e| ReadError::new("ChannelRole", format!("Failed to read u8: {e}")))?;
        ChannelRole::try_from(v)
    }
}

impl TryFrom<u8> for ChannelRole {
    type Error = ReadError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ChannelRole::Merchant),
            1 => Ok(ChannelRole::Customer),
            _ => Err(ReadError::new(
                "ChannelRole",
                format!("Invalid representation for ChannelRole: {value}"),
            )),
        }
    }
}

impl AsRef<[u8]> for ChannelRole {
    fn as_ref(&self) -> &[u8] {
        match self {
            ChannelRole::Merchant => &[0],
            ChannelRole::Customer => &[1],
        }
    }
}

impl Writable for ChannelRole {
    fn write<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        writer.emit_u8(self.as_u8())
    }
}
