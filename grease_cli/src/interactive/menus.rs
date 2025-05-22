//! Interactive menu options.
//!
//! Commands must be unique across all menus. If the same name is used in multiple menus, the same function will be
//! called for each menu that contains the command.
pub type Menu = (&'static str, &'static [&'static str]);

// Command aliases. Keep this list in alphabetical order.
pub mod commands {
    pub const ADD_IDENTITY: &str = "Add identity";
    pub const CLOSE_CHANNEL: &str = "Close channel co-operatively";
    pub const CONNECT_TO_CHANNEL: &str = "Connect to channel";
    pub const DISPUTE_CHANNEL_CLOSE: &str = "Dispute the forced closure of a channel";
    pub const EXIT: &str = "Exit";
    pub const FORCE_CLOSE_CHANNEL: &str = "Force Close the channel";
    pub const LIST_CHANNELS: &str = "List channels";
    pub const LIST_IDENTITIES: &str = "List identities";
    pub const NAV_BACK: &str = "Back";
    pub const NAV_TO_CUSTOMER_MENU: &str = "For Customers";
    pub const NAV_TO_IDENTITY_MENU: &str = "Manage Identities";
    pub const NAV_TO_MERCHANT_MENU: &str = "For Merchants";
    pub const PAYMENT_REQUEST: &str = "Request payment";
    pub const PAYMENT_SEND: &str = "Send payment";
    pub const PROPOSE_CHANNEL: &str = "Initiate new channel";
    pub const REMOVE_IDENTITY: &str = "Remove identity";
    pub const SHARE_MERCHANT_INFO: &str = "Display new channel QR code";
    // Debugging commands only
    pub const SUBMIT_FUNDING_TX: &str = "Submit funding transactions";
}

pub use commands::*;

pub const TOP_MENU: [&str; 4] = [NAV_TO_CUSTOMER_MENU, NAV_TO_MERCHANT_MENU, NAV_TO_IDENTITY_MENU, EXIT];

pub const IDENTITY_MENU: [&str; 7] = [
    LIST_IDENTITIES,
    ADD_IDENTITY,
    REMOVE_IDENTITY,
    NAV_TO_CUSTOMER_MENU,
    NAV_TO_MERCHANT_MENU,
    NAV_BACK,
    EXIT,
];

pub const CUSTOMER_MENU: [&str; 12] = [
    CONNECT_TO_CHANNEL,
    PROPOSE_CHANNEL,
    SUBMIT_FUNDING_TX,
    LIST_CHANNELS,
    PAYMENT_SEND,
    PAYMENT_REQUEST,
    NAV_TO_IDENTITY_MENU,
    NAV_BACK,
    CLOSE_CHANNEL,
    FORCE_CLOSE_CHANNEL,
    DISPUTE_CHANNEL_CLOSE,
    EXIT,
];

pub const MERCHANT_MENU: [&str; 12] = [
    CONNECT_TO_CHANNEL,
    SHARE_MERCHANT_INFO,
    LIST_CHANNELS,
    PAYMENT_SEND,
    PAYMENT_REQUEST,
    NAV_TO_IDENTITY_MENU,
    NAV_BACK,
    CLOSE_CHANNEL,
    FORCE_CLOSE_CHANNEL,
    DISPUTE_CHANNEL_CLOSE,
    EXIT,
    // Debugging commands only
    SUBMIT_FUNDING_TX,
];

pub fn top_menu() -> &'static Menu {
    &("Main", &TOP_MENU)
}

pub fn identity_menu() -> &'static Menu {
    &("Identities", &IDENTITY_MENU)
}

pub fn customer_menu() -> &'static Menu {
    &("Customers", &CUSTOMER_MENU)
}

pub fn merchant_menu() -> &'static Menu {
    &("Merchants", &MERCHANT_MENU)
}
