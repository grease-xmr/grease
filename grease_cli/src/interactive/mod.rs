use crate::interactive::menus::{top_menu, Menu};
use grease_p2p::{ConversationIdentity, NetworkServer, OutOfBandMerchantInfo, PaymentChannels};
use std::fmt::Display;
use std::str::FromStr;

pub mod formatting;
pub mod menus;
use crate::config::{default_config_path, GlobalOptions};
use crate::id_management::{
    assign_identity, create_identity, delete_identity, list_identities, load_or_create_identities,
};
use crate::interactive::formatting::qr_code;
use anyhow::{anyhow, Result};
use dialoguer::{console::Style, theme::ColorfulTheme, FuzzySelect};
use grease_p2p::delegates::DummyDelegate;
use grease_p2p::message_types::NewChannelProposal;
use libgrease::amount::MoneroAmount;
use libgrease::balance::Balances;
use libgrease::state_machine::lifecycle::LifecycleStage;
use libgrease::state_machine::ChannelSeedBuilder;
use log::*;
use menus::*;
use monero::Address;
use rand::{Rng, RngCore};

pub type MoneroNetworkServer = NetworkServer<DummyDelegate>;
pub const RPC_ADDRESS: &str = "http://localhost:25070";

pub struct InteractiveApp {
    identity: ConversationIdentity,
    config: GlobalOptions,
    current_menu: &'static Menu,
    breadcrumbs: Vec<&'static Menu>,
    current_channel: Option<String>,
    channel_status: Option<LifecycleStage>,
    server: NetworkServer<DummyDelegate>,
}

impl InteractiveApp {
    /// Creates a new `InteractiveApp` instance with the provided configuration.
    ///
    /// Initializes the key manager with a secret from the configuration or generates a random one if absent. Loads identities from the configured file if available, sets up the initial menu state, and attempts to auto-login using a preferred identity if specified.
    pub fn new(config: GlobalOptions) -> Result<Self, anyhow::Error> {
        let current_menu = top_menu();
        let breadcrumbs = vec![top_menu()];
        let id_path = config.identities_file.clone().unwrap_or_else(|| config.base_path().join("identities.yml"));
        let identity = assign_identity(&id_path, config.preferred_identity.as_ref())?;
        let delegate = DummyDelegate::default();
        let channels = PaymentChannels::load(config.channel_directory())?;
        let server = MoneroNetworkServer::new(identity.clone(), channels, RPC_ADDRESS, delegate)?;
        let app =
            Self { identity, current_menu, breadcrumbs, config, current_channel: None, channel_status: None, server };
        Ok(app)
    }

    pub async fn save_channels(&self) -> Result<()> {
        self.server.save_channels(&self.config.channel_directory()).await?;
        Ok(())
    }

    async fn update_status(&mut self) {
        if let Some(name) = self.current_channel.as_ref() {
            let status = self.server.channel_status(name.as_str()).await;
            self.channel_status = status;
        }
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
        let status = match (self.current_channel.as_ref(), self.channel_status) {
            (Some(channel), Some(stage)) => &format!("{channel} ({stage})"),
            (Some(channel), None) => &format!("{channel} (No status)"),
            (None, _) => "No active channel",
        };
        format!("\n{breadcrumbs:-30}{status:60}{p2p_identity:60}\n[Ready]")
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
            // Refresh channel lifecycle stage before showing the menu
            self.update_status().await;
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
                PROPOSE_CHANNEL => handle_response(self.propose_new_channel().await),
                SUBMIT_FUNDING_TX => handle_response(self.submit_funding_tx().await),
                CONNECT_TO_CHANNEL => handle_response(self.connect_to_channel().await),
                CLOSE_CHANNEL => handle_response(self.close_channel().await),
                DISPUTE_CHANNEL_CLOSE => println!("Coming soon"),
                FORCE_CLOSE_CHANNEL => println!("Coming soon"),
                LIST_CHANNELS => self.print_channel_names().await,
                PAYMENT_SEND => handle_response(self.send_payment().await),
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

    async fn connect_to_channel(&mut self) -> Result<String> {
        let channel = self.select_channel().await?;
        self.current_channel = Some(channel.clone());
        self.update_status().await;
        if let Some(LifecycleStage::Establishing) = self.channel_status {
            debug!("Establishing channel. Checking whether we should rescan for funding transaction..");
            self.server.rescan_for_funding(&channel).await;
        }
        if let Some(LifecycleStage::Closing) = self.channel_status {
            debug!("Channel is closing. Rebroadcasting closing transaction..");
            self.server.rebroadcast_closing_transaction(&channel).await?;
        }
        Ok("Channel {channel} selected".to_string())
    }

    async fn submit_funding_tx(&mut self) -> Result<String> {
        if self.current_channel.is_none() {
            return Err(anyhow!("No channel selected"));
        }
        let name = self.current_channel.clone().unwrap();
        let info = self.server.channel_metadata(&name).await.ok_or_else(|| anyhow!("No channel metadata found"))?;
        let balances = info.balances().customer;
        let address = self
            .server
            .wallet_address(&name, "mainnet")
            .await
            .map_err(|e| anyhow!("Error getting wallet channel address: {}", e))?;
        Ok(format!("Send {balances} to {address} to fund the channel"))
    }

    async fn print_channel_names(&self) {
        let channels = self.server.list_channels().await;
        if channels.is_empty() {
            return println!("No channels found.");
        }
        let names = channels.join("\n");
        println!("Found {} channels:\n{}", channels.len(), names);
    }

    async fn propose_new_channel(&mut self) -> Result<String> {
        // Get the merchant details and add our info
        let oob_info = dialoguer::Input::<String>::new().with_prompt("Paste merchant info").interact()?;
        let oob_info = serde_json::from_str::<OutOfBandMerchantInfo>(&oob_info)?;
        let address = match self.config.refund_address {
            Some(addr) => addr,
            None => {
                let address =
                    dialoguer::Input::<String>::new().with_prompt("Paste return Monero address").interact()?;
                Address::from_str(&address).map_err(|e| anyhow!("Invalid address: {e}"))?
            }
        };
        let proposal = self.create_channel_proposal(oob_info, address)?;
        trace!("Generated new proposal");
        // Send the proposal to the merchant and wait for reply
        let name = self.server.establish_new_channel(proposal.clone()).await?;
        self.save_channels().await?;
        info!("Channels saved.");
        self.current_channel = Some(name.clone());
        let status = self.server.channel_status(&name).await;
        self.channel_status = status;
        Ok(format!("New channel created: {name}"))
    }

    async fn send_payment(&mut self) -> Result<String> {
        if self.current_channel.is_none() {
            return Err(anyhow!("No channel selected"));
        }
        let name = self.current_channel.as_ref().expect("Just checked that a channel is selected");
        let info = self.server.channel_metadata(name).await.ok_or_else(|| anyhow!("No channel metadata found"))?;
        let customer_balance = info.balances().customer;
        let amount = dialoguer::Input::<String>::new()
            .with_prompt(format!("Send amount (available: {customer_balance})"))
            .interact()?;
        let amount = MoneroAmount::from_xmr(&amount).ok_or_else(|| anyhow!("Invalid XMR value"))?;
        // We could easily add a check here to ensure the amount is not greater than the available balance
        // but let's test that the channel handles this edge case too.
        let update = self.server.pay(name, amount).await?;
        let update_count = update.update_count;
        let merchant = update.new_balances.merchant;
        let customer = update.new_balances.customer;
        let total = update.new_balances.total();
        let result = format!(
            r#"
------------------------------------------------------------------------------
|        Balance update #{update_count:3} for channel {name:<35} |
|        Payment amount:   {amount:20}                                   |
|        Merchant balance: {merchant:20}                                   |
|        Customer balance: {customer:20}                                   |
|        Total:            {total:20}                                   |
------------------------------------------------------------------------------"#
        );
        Ok(result)
    }

    async fn close_channel(&mut self) -> Result<String> {
        if self.current_channel.is_none() {
            return Err(anyhow!("No channel selected"));
        }
        let name = self.current_channel.as_ref().expect("Just checked that a channel is selected");
        let closing_balance = self.server.close_channel(name).await?;
        self.save_channels().await?;
        info!("Channels saved.");
        Ok(format!(
            "Channel {name} closed successfully. Final transaction should be broadcast shortly.\n\
        Closing balances:\n\
        Merchant: {:15}\n\
        Customer: {:15}\n\
        Total:    {:15}",
            closing_balance.merchant,
            closing_balance.customer,
            closing_balance.total()
        ))
    }

    pub fn create_channel_proposal(
        &self,
        oob_info: OutOfBandMerchantInfo,
        my_closing_address: Address,
    ) -> Result<NewChannelProposal, anyhow::Error> {
        let my_contact_info = self.identity.contact_info();
        let peer_info = oob_info.contact;
        let seed_info = oob_info.seed;
        let key_index = rand::rng().next_u64();
        let user_label = self.identity.id();
        let my_user_label = format!("{user_label}-{key_index}");
        let proposal =
            NewChannelProposal::new(seed_info, my_user_label, my_contact_info, my_closing_address, peer_info);
        Ok(proposal)
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
        // For now, we only support merchant balance of 0.0
        let balances = Balances::new(
            MoneroAmount::from_xmr("0.0").ok_or_else(|| anyhow!("Invalid merchant balance"))?,
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
        let address = self
            .config
            .refund_address()
            .ok_or_else(|| anyhow!("No refund address found. Is `refund_address` configured in the config file?"))?;
        let seed_info = ChannelSeedBuilder::default()
            .with_key_id(index)
            .with_kes_public_key(kes)
            .with_initial_balances(balances)
            .with_user_label(channel_id)
            .with_closing_address(address)
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
