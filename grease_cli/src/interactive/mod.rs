use crate::interactive::menus::{top_menu, Menu};
use grease_p2p::{ConversationIdentity, DummyDelegate, KeyManager, OutOfBandMerchantInfo, PaymentChannels};
use std::fmt::Display;

pub mod formatting;
pub mod menus;
use crate::channel_management::{
    MoneroChannelBuilder, MoneroLifeCycle, MoneroNetworkServer, MoneroOutOfBandMerchantInfo, MoneroPaymentChannel,
};
use crate::config::{default_config_path, GlobalOptions};
use crate::id_management::{
    assign_identity, create_identity, delete_identity, list_identities, load_or_create_identities, MoneroKeyManager,
};
use crate::interactive::formatting::qr_code;
use anyhow::{anyhow, Result};
use dialoguer::{console::Style, theme::ColorfulTheme, FuzzySelect};
use grease_p2p::message_types::{ChannelProposalResult, NewChannelProposal};
use libgrease::amount::MoneroAmount;
use libgrease::crypto::keys::{Curve25519PublicKey, Curve25519Secret};
use libgrease::state_machine::{Balances, ChannelSeedBuilder};
use log::*;
use menus::*;
use rand::{Rng, RngCore};

pub struct InteractiveApp {
    identity: ConversationIdentity,
    config: GlobalOptions,
    current_menu: &'static Menu,
    breadcrumbs: Vec<&'static Menu>,
    current_channel: Option<String>,
    server: MoneroNetworkServer,
}

impl InteractiveApp {
    /// Creates a new `InteractiveApp` instance with the provided configuration.
    ///
    /// Initializes the key manager with a secret from the configuration or generates a random one if absent. Loads identities from the configured file if available, sets up the initial menu state, and attempts to auto-login using a preferred identity if specified.
    pub fn new(config: GlobalOptions) -> Result<Self, anyhow::Error> {
        let current_menu = top_menu();
        let breadcrumbs = vec![top_menu()];
        let Some(secret) = config.initial_secret() else {
            error!("No `initial_secret` found in config file.");
            return Err(anyhow!("No `initial_secret` found in config file."));
        };
        let key_manager = MoneroKeyManager::new(secret);
        let id_path = config.identities_file.clone().unwrap_or_else(|| config.base_path().join("identities.yml"));
        let identity = assign_identity(&id_path, config.preferred_identity.as_ref())?;
        let delegate = DummyDelegate;
        let channels = PaymentChannels::load(&config.channel_directory())?;
        let server = MoneroNetworkServer::new(identity.clone(), channels, delegate, key_manager)?;
        let app = Self { identity, current_menu, breadcrumbs, config, current_channel: None, server };
        Ok(app)
    }

    pub async fn save_channels(&self) -> Result<()> {
        self.server.save_channels(&self.config.channel_directory()).await?;
        Ok(())
    }

    async fn select_channel(&mut self) -> Result<String> {
        let channels = self.server.list_channels().await;
        if channels.is_empty() {
            return Err(anyhow!("No channels found"));
        }
        let theme = ColorfulTheme { prompt_style: Style::new().magenta().bold(), ..ColorfulTheme::default() };
        let i = FuzzySelect::with_theme(&theme).with_prompt("Select channel").items(&channels).interact()?;
        let name = &channels[i];
        Ok(name.clone())
    }

    /// Constructs a formatted prompt string displaying the current menu navigation path and login status.
    ///
    /// The prompt shows the breadcrumb trail of menus and either the current identity's ID or a "Not logged in" message.
    fn menu_prompt(&self) -> String {
        let breadcrumbs = self.breadcrumbs.iter().map(|m| m.0).collect::<Vec<&str>>().join(" » ");
        let p2p_identity = format!("{}@{}", self.identity.id(), self.identity.peer_id());
        let status = match self.current_channel {
            Some(ref channel) => channel.as_str(),
            None => "No active channel",
        };
        format!("\n{breadcrumbs:-30}{status:50}{p2p_identity:70}\n[Ready]")
    }

    fn pop_menu(&mut self) {
        if self.breadcrumbs.len() > 1 {
            self.breadcrumbs.pop();
            self.current_menu = self.breadcrumbs.last().unwrap_or(&top_menu());
        }
    }

    fn select_menu(&mut self, menu: &'static Menu) {
        self.breadcrumbs.push(menu);
        self.current_menu = menu;
    }

    pub async fn run(&mut self) -> Result<()> {
        print_logo();
        let at = self.identity.dial_address();
        self.server.start_listening(at).await?;
        loop {
            let theme = ColorfulTheme { prompt_style: Style::new().magenta().bold(), ..ColorfulTheme::default() };
            let i = FuzzySelect::with_theme(&theme)
                .with_prompt(self.menu_prompt())
                .items(self.current_menu.1)
                .interact()?;
            match self.current_menu.1[i] {
                NAV_BACK => self.pop_menu(),
                NAV_TO_CUSTOMER_MENU => self.select_menu(customer_menu()),
                NAV_TO_MERCHANT_MENU => self.select_menu(merchant_menu()),
                NAV_TO_IDENTITY_MENU => self.select_menu(identity_menu()),
                EXIT => break,
                ADD_IDENTITY => handle_response(self.create_identity()),
                REMOVE_IDENTITY => handle_response(self.delete_identity()),
                LIST_IDENTITIES => handle_response(self.list_identities()),
                SHARE_MERCHANT_INFO => handle_response(self.share_merchant_info()),
                PROPOSE_CHANNEL => handle_response(self.initiate_new_channel().await),
                CLOSE_CHANNEL => println!("Coming soon"),
                DISPUTE_CHANNEL_CLOSE => println!("Coming soon"),
                FORCE_CLOSE_CHANNEL => println!("Coming soon"),
                LIST_CHANNELS => self.print_channel_names().await,
                PAYMENT_REQUEST => println!("Coming soon"),
                PAYMENT_SEND => println!("Coming soon"),
                _ => continue,
            }
        }
        Ok(())
    }

    fn create_identity(&mut self) -> Result<String> {
        let name = dialoguer::Input::<String>::new().with_prompt("Enter new identity name").interact()?;
        let id = create_identity(&self.config, Some(name))?;
        Ok(id.to_string())
    }

    async fn print_channel_names(&self) {
        let channels = self.server.list_channels().await;
        if channels.is_empty() {
            return println!("No channels found.");
        }
        let names = channels.join("\n");
        println!("Found {} channels:\n{}", channels.len(), names);
    }

    /// Propose a new channel
    ///
    /// One peer, usually the customer, will propose a new channel by connecting to the merchant over the P2P network.
    /// and submitting the channel proposal. The information, such as pubkeys, initial balances, etc., is partially
    /// from the customer, but some will have been provided by the merchant  out-of-band (see
    /// [`Self::share_merchant_info`]).
    ///
    /// If the merchant accepts the proposal, they will send a message back to the customer with the channel ID, and
    /// we can progress to the Establishing state.
    async fn initiate_new_channel(&mut self) -> Result<String> {
        let oob_info = dialoguer::Input::<String>::new().with_prompt("Paste merchant info").interact()?;
        let oob_info = serde_json::from_str::<MoneroOutOfBandMerchantInfo>(&oob_info)?;
        let (secret, proposal) = self.create_channel_proposal(oob_info)?;
        trace!("Generated new proposal");
        let result = self.server.send_proposal(proposal.clone()).await?;
        match result {
            ChannelProposalResult::Accepted(final_proposal) => {
                info!("🥂 Channel proposal accepted!");
                let channel = self.create_channel(secret, final_proposal, proposal)?;
                let name = channel.name();
                self.server.add_channel(channel).await;
                self.save_channels().await?;
                info!("Channels saved.");
                self.current_channel = Some(name.clone());
                Ok(format!("Channel proposal accepted! Channel ID: {name}"))
            }
            ChannelProposalResult::Rejected(rej) => {
                warn!("Channel proposal rejected: {}", rej.reason);
                // todo: handle the rejection based on retry options
                Err(anyhow!("Channel proposal rejected"))
            }
        }
    }

    pub fn create_channel_proposal(
        &self,
        oob_info: MoneroOutOfBandMerchantInfo,
    ) -> Result<(Curve25519Secret, NewChannelProposal<Curve25519PublicKey>), anyhow::Error> {
        let my_contact_info = self.identity.contact_info();
        let peer_info = oob_info.contact;
        let seed_info = oob_info.seed;
        let key_index = rand::rng().next_u64();
        let (my_secret, my_pubkey) = self.server.key_manager().new_keypair(key_index);
        let user_label = self.identity.id();
        let my_user_label = format!("{user_label}-{key_index}");
        let proposal = NewChannelProposal::new(seed_info, my_pubkey, my_user_label, my_contact_info, peer_info);
        Ok((my_secret, proposal))
    }

    pub fn create_channel(
        &mut self,
        secret: Curve25519Secret,
        final_prop: NewChannelProposal<Curve25519PublicKey>,
        original: NewChannelProposal<Curve25519PublicKey>,
    ) -> Result<MoneroPaymentChannel, anyhow::Error> {
        self.compare_proposals(&final_prop, &original)?;
        let peer_info = final_prop.contact_info_proposee;
        let new_state = MoneroChannelBuilder::new(final_prop.seed.role, final_prop.proposer_pubkey, secret)
            .with_my_user_label(&final_prop.proposer_label)
            .with_peer_label(&final_prop.seed.user_label)
            .with_merchant_initial_balance(final_prop.seed.initial_balances.merchant)
            .with_customer_initial_balance(final_prop.seed.initial_balances.customer)
            .with_peer_public_key(final_prop.seed.pubkey)
            .with_kes_public_key(final_prop.seed.kes_public_key)
            .build::<blake2::Blake2b512>()
            .ok_or_else(|| anyhow!("Missing new channel state data"))?;
        let state = MoneroLifeCycle::New(Box::new(new_state));
        let channel = MoneroPaymentChannel::new(peer_info, state);
        Ok(channel)
    }

    fn compare_proposals(
        &self,
        _final_proposal: &NewChannelProposal<Curve25519PublicKey>,
        _original: &NewChannelProposal<Curve25519PublicKey>,
    ) -> Result<(), anyhow::Error> {
        // todo: Check that we're happy with the final terms sent by the merchant
        Ok(())
    }

    /// Lists all available identities from the configuration.
    ///
    /// Returns a formatted string containing the number of identities found and their names.
    fn list_identities(&mut self) -> Result<String> {
        let id = list_identities(&self.config)?;
        Ok(format!("Found {} identities:\n{}", id.len(), id.join("\n")))
    }

    /// Deletes a selected identity from the local identities file.
    ///
    /// Prompts the user to choose an identity to delete, removes it from the configured identities file, and returns a confirmation message.
    fn delete_identity(&mut self) -> Result<String> {
        let path = self.config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
        let local_identities = load_or_create_identities(&path)?;
        let names = local_identities.ids().cloned().collect::<Vec<String>>();
        let i = FuzzySelect::new().with_prompt("Select identity to delete").items(&names).interact()?;
        let name = &names[i];
        delete_identity(&self.config, name)?;
        Ok(format!("Identity {name} deleted"))
    }

    /// Prompts for initial balances and generates merchant channel info as a QR code and JSON string.
    /// # Returns
    /// A formatted string containing the QR code and the JSON-encoded merchant channel information.
    ///
    /// # Errors
    /// Returns an error if the user is not logged in, required configuration fields are missing, balances are
    /// invalid, or serialization fails.
    fn share_merchant_info(&mut self) -> Result<String> {
        let valid_xmr = |v: &String| -> Result<(), &str> {
            match MoneroAmount::from_xmr(v) {
                Some(_) => Ok(()),
                None => Err("Not a valid XMR value."),
            }
        };
        let customer_balance = dialoguer::Input::<String>::new()
            .with_prompt("Enter customer initial balance")
            .validate_with(valid_xmr)
            .interact()?;
        let merchant_balance = dialoguer::Input::<String>::new()
            .with_prompt("Enter merchant initial balance")
            .validate_with(valid_xmr)
            .interact()?;
        let balances = Balances::new(
            MoneroAmount::from_xmr(&merchant_balance).ok_or_else(|| anyhow!("Invalid merchant balance"))?,
            MoneroAmount::from_xmr(&customer_balance).ok_or_else(|| anyhow!("Invalid customer balance"))?,
        );
        let contact_info = self.identity.contact_info();
        let kes = self
            .config
            .kes_public_key()
            .ok_or_else(|| anyhow!("No KES public key found. Is `kes_public_key` configured in the config file?"))?;
        let label = self
            .config
            .user_label()
            .ok_or_else(|| anyhow!("No user label found. Is `user_label` configured in the config file?"))?;
        let index = rand::rng().random();
        let channel_id = format!("{label}-{index}");
        let (_secret, channel_pubkey) = self.server.key_manager().new_keypair(index);
        let seed_info = ChannelSeedBuilder::default()
            .with_pubkey(channel_pubkey)
            .with_key_id(index)
            .with_kes_public_key(kes)
            .with_initial_balances(balances)
            .with_user_label(channel_id)
            .build()?;
        let info = OutOfBandMerchantInfo::new(contact_info, seed_info);
        let val = serde_json::to_string(&info)?;
        let qr = qr_code(&val);
        Ok(format!("Channel info:\n{qr}\n{val}"))
    }
}

fn print_logo() {
    const LOGO: &str = include_str!("../../../assets/logo.txt");
    println!("{LOGO}");
}

fn handle_response<T: Display>(res: Result<T>) {
    match res {
        Ok(res) => println!("Ok.\n{res}\n\n"),
        Err(e) => println!("Error.\n{}", e),
    }
}
