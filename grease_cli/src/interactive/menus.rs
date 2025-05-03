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
    pub const LOGOUT: &str = "Logout";
    pub const MAKE_PAYMENT_ON_CHANNEL: &str = "Make a payment on channel";
    pub const NAV_BACK: &str = "Back";
    pub const NAV_TO_CHANNELS_MENU: &str = "Payment Channels Menu";
    pub const NAV_TO_IDENTITY_MENU: &str = "Identity Menu";
    pub const PROPOSE_CHANNEL: &str = "Create New channel";
    pub const REMOVE_IDENTITY: &str = "Remove identity";
}

pub use commands::*;

pub const TOP_MENU: [&str; 3] = [NAV_TO_CHANNELS_MENU, NAV_TO_IDENTITY_MENU, EXIT];

pub const IDENTITY_MENU: [&str; 7] =
    [ADD_IDENTITY, LIST_IDENTITIES, LOGOUT, REMOVE_IDENTITY, NAV_TO_CHANNELS_MENU, NAV_BACK, EXIT];

pub const CHANNELS_MENU: [&str; 6] =
    [CONNECT_TO_CHANNEL, PROPOSE_CHANNEL, LIST_CHANNELS, NAV_TO_IDENTITY_MENU, NAV_BACK, EXIT];

pub const ACTIVE_CHANNEL_MENU: [&str; 6] =
    [MAKE_PAYMENT_ON_CHANNEL, CLOSE_CHANNEL, FORCE_CLOSE_CHANNEL, DISPUTE_CHANNEL_CLOSE, NAV_BACK, EXIT];

pub fn top_menu() -> &'static Menu {
    &("Main", &TOP_MENU)
}

pub fn identity_menu() -> &'static Menu {
    &("Identities", &IDENTITY_MENU)
}

pub fn channels_menu() -> &'static Menu {
    &("Payment Channels", &CHANNELS_MENU)
}

pub fn active_channel_menu() -> &'static Menu {
    &("Active Channel", &ACTIVE_CHANNEL_MENU)
}
