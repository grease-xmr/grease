use crate::interactive::menus::{top_menu, Menu};
use grease_p2p::{ContactInfo, ConversationIdentity};
use std::fmt::Display;

pub mod formatting;
pub mod menus;
use crate::channel_management::OutOfBandMerchantInfo;
use crate::config::GlobalOptions;
use crate::id_management::{
    create_identity, default_config_path, delete_identity, list_identities, load_or_create_identities, KeyManager,
    LocalIdentitySet,
};
use crate::interactive::formatting::qr_code;
use anyhow::{anyhow, Result};
use dialoguer::theme::Theme;
use dialoguer::{console::Style, theme::ColorfulTheme, FuzzySelect};
use libgrease::amount::MoneroAmount;
use libgrease::crypto::keys::Curve25519Secret;
use libgrease::state_machine::{Balances, ChannelSeedBuilder};
use log::{info, warn};
use menus::*;
use rand::Rng;

pub struct InteractiveApp {
    identity: Option<ConversationIdentity>,
    config: GlobalOptions,
    identities: Option<LocalIdentitySet>,
    current_menu: &'static Menu,
    breadcrumbs: Vec<&'static Menu>,
    key_manager: KeyManager,
}

impl InteractiveApp {
    pub fn new(config: GlobalOptions) -> Self {
        let identity = None;
        let current_menu = top_menu();
        let breadcrumbs = vec![top_menu()];
        let secret = config.initial_secret().unwrap_or_else(|| {
            warn!("No `initial_secret` found in config file. Generating a random one.");
            Curve25519Secret::random(&mut rand::rng())
        });
        let key_manager = KeyManager::new(secret);
        let identities = config.identities_file.as_ref().map(|p| load_or_create_identities(&p).ok()).flatten();
        let mut app = Self { identity, current_menu, breadcrumbs, config, identities, key_manager };
        if let Some(id) = app.config.preferred_identity.clone() {
            app.login_as(&id);
        }
        app
    }

    pub fn is_logged_in(&self) -> bool {
        self.identity.is_some()
    }

    pub fn login(&mut self) -> Result<String> {
        if self.is_logged_in() {
            return Ok("Logged In".to_string());
        }
        let theme = ColorfulTheme { values_style: Style::new().yellow().dim(), ..ColorfulTheme::default() };
        let (name, id) = self.select_identity(&theme)?;
        self.login_as(&name).ok_or_else(|| anyhow!("Identity not found"))?;
        Ok(format!("Logged in as {name}"))
    }

    pub fn login_as<'a>(&mut self, name: &'a str) -> Option<&'a str> {
        self.identities
            .as_ref()
            .and_then(|ids| ids.get(name).cloned())
            .and_then(|mut id| match (id.address(), self.config.server_address()) {
                (None, Some(config_addr)) => {
                    info!("Setting identity address from config file");
                    id.set_address(config_addr);
                    Some(id)
                }
                _ => Some(id),
            })
            .map(|id| {
                self.identity = Some(id);
                name
            })
    }

    pub fn menu_prompt(&self) -> String {
        let breadcrumbs = self.breadcrumbs.iter().map(|m| m.0).collect::<Vec<&str>>().join(" » ");
        let status = if self.is_logged_in() {
            self.identity.as_ref().map(|identity| identity.id()).unwrap_or("Unknown")
        } else {
            "Not logged in"
        };
        format!("{breadcrumbs:-30}{status:50}")
    }

    pub fn pop_menu(&mut self) {
        if self.breadcrumbs.len() > 1 {
            self.breadcrumbs.pop();
            self.current_menu = self.breadcrumbs.last().unwrap_or(&top_menu());
        }
    }

    pub fn select_menu(&mut self, menu: &'static Menu) {
        self.breadcrumbs.push(menu);
        self.current_menu = menu;
    }

    pub async fn run(&mut self) -> Result<()> {
        print_logo();
        loop {
            let theme = ColorfulTheme { prompt_style: Style::new().magenta().bold(), ..ColorfulTheme::default() };
            let i = FuzzySelect::with_theme(&theme)
                .with_prompt(self.menu_prompt())
                .items(self.current_menu.1)
                .interact()?;
            match self.current_menu.1[i] {
                LOGOUT => self.logout(),
                NAV_BACK => self.pop_menu(),
                NAV_TO_CUSTOMER_MENU => self.select_menu(customer_menu()),
                NAV_TO_MERCHANT_MENU => self.select_menu(merchant_menu()),
                NAV_TO_IDENTITY_MENU => self.select_menu(identity_menu()),
                EXIT => break,
                ADD_IDENTITY => handle_response(self.create_identity()),
                REMOVE_IDENTITY => handle_response(self.delete_identity()),
                LIST_IDENTITIES => handle_response(self.list_identities()),
                SHARE_MERCHANT_INFO => handle_response(self.share_merchant_info()),
                CLOSE_CHANNEL => println!("Coming soon"),
                CONNECT_TO_CHANNEL => println!("Coming soon"),
                DISPUTE_CHANNEL_CLOSE => println!("Coming soon"),
                FORCE_CLOSE_CHANNEL => println!("Coming soon"),
                LIST_CHANNELS => println!("Coming soon"),
                PAYMENT_REQUEST => println!("Coming soon"),
                PAYMENT_SEND => println!("Coming soon"),
                PROPOSE_CHANNEL => println!("Coming soon"),
                _ => continue,
            }
        }
        Ok(())
    }

    fn logout(&mut self) {
        self.identity = None;
        println!("Logged out");
    }

    fn create_identity(&mut self) -> Result<String> {
        let name = dialoguer::Input::<String>::new().with_prompt("Enter new identity name").interact()?;
        let id = create_identity(&self.config, Some(name))?;
        Ok(id.to_string())
    }

    fn list_identities(&mut self) -> Result<String> {
        let id = list_identities(&self.config)?;
        Ok(format!("Found {} identities:\n{}", id.len(), id.join("\n")))
    }

    fn select_identity(&mut self, theme: &dyn Theme) -> Result<(String, &ConversationIdentity)> {
        let ids = match self.identities {
            Some(ref identities) => identities,
            None => {
                let path = self
                    .config
                    .identities_file
                    .as_ref()
                    .cloned()
                    .ok_or_else(|| anyhow!("Identity file location not specified in config file"))?;
                let local_identities = load_or_create_identities(&path)?;
                self.identities = Some(local_identities);
                self.identities.as_ref().expect("Should never be None")
            }
        };
        let names = ids.ids().cloned().collect::<Vec<String>>();
        let i = FuzzySelect::with_theme(theme).with_prompt("Select identity").items(&names).interact()?;
        let name = &names[i];
        Ok((name.to_string(), ids.get(name).expect("Identity should exist")))
    }

    fn delete_identity(&mut self) -> Result<String> {
        let path = self.config.identities_file.as_ref().cloned().unwrap_or_else(default_config_path);
        let local_identities = load_or_create_identities(&path)?;
        let names = local_identities.ids().cloned().collect::<Vec<String>>();
        let i = FuzzySelect::new().with_prompt("Select identity to delete").items(&names).interact()?;
        let name = &names[i];
        delete_identity(&self.config, name)?;
        Ok(format!("Identity {name} deleted"))
    }

    fn share_merchant_info(&mut self) -> Result<String> {
        if !self.is_logged_in() {
            let _ = self.login()?;
        }
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
        let contact_info =
            self.identity.as_ref().map(|id| id.contact_info()).flatten().ok_or_else(|| {
                anyhow!("No contact info found. Is the server address is configured in the config file?")
            })?;
        let kes = self
            .config
            .kes_public_key()
            .ok_or_else(|| anyhow!("No KES public key found. Is `kes_public_key` configured in the config file?"))?;
        let label = self
            .config
            .user_label()
            .ok_or_else(|| anyhow!("No user label found. Is `user_label` configured in the config file?"))?;
        let index = rand::rng().random();
        // Definitely not the way to do this in production, but hacking this in for now
        let channel_id = format!("{label}-{index}");
        let (_secret, channel_pubkey) = self.key_manager.new_keypair(index);
        let seed_info = ChannelSeedBuilder::default()
            .with_pubkey(channel_pubkey)
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
