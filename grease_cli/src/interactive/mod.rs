use crate::interactive::menus::{top_menu, Menu};
use grease_p2p::ChannelIdentity;
use std::fmt::Display;

pub mod formatting;
pub mod menus;
use crate::config::GlobalOptions;
use crate::id_management::{
    create_identity, default_id_path, delete_identity, list_identities, load_or_create_identities,
};
use anyhow::{anyhow, Result};
use dialoguer::{console::Style, theme::ColorfulTheme, FuzzySelect};
use menus::*;

pub struct InteractiveApp {
    identity: Option<ChannelIdentity>,
    config: GlobalOptions,
    current_menu: &'static Menu,
    breadcrumbs: Vec<&'static Menu>,
}

impl InteractiveApp {
    pub fn new(config: GlobalOptions) -> Self {
        let identity = None;
        let current_menu = top_menu();
        let breadcrumbs = vec![top_menu()];
        Self { identity, current_menu, breadcrumbs, config }
    }

    pub fn is_logged_in(&self) -> bool {
        self.identity.is_some()
    }

    pub async fn login(&mut self) -> Result<String> {
        if self.is_logged_in() {
            return Ok("Logged In".to_string());
        }
        let theme = ColorfulTheme { values_style: Style::new().yellow().dim(), ..ColorfulTheme::default() };
        self.identity = select_identity(&theme, &self.config);
        Ok("Logged In".to_string())
    }

    pub fn menu_prompt(&self) -> String {
        let breadcrumbs = self.breadcrumbs.iter().map(|m| m.0).collect::<Vec<&str>>().join(" » ");
        let status = if self.is_logged_in() {
            let identity = self.identity.as_ref().expect("User is logged in. Identity should not be None");
            identity.id()
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
                CLOSE_CHANNEL => println!("Coming soon"),
                CONNECT_TO_CHANNEL => println!("Coming soon"),
                DISPUTE_CHANNEL_CLOSE => println!("Coming soon"),
                FORCE_CLOSE_CHANNEL => println!("Coming soon"),
                LIST_CHANNELS => println!("Coming soon"),
                PAYMENT_REQUEST => println!("Coming soon"),
                PAYMENT_SEND => println!("Coming soon"),
                PROPOSE_CHANNEL => println!("Coming soon"),
                SHARE_MERCHANT_INFO => println!("Coming soon"),
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

    fn delete_identity(&mut self) -> Result<String> {
        let path = self.config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
        let local_identities = load_or_create_identities(&path)?;
        let names = local_identities.ids().cloned().collect::<Vec<String>>();
        let i = FuzzySelect::new().with_prompt("Select identity to delete").items(&names).interact()?;
        let name = &names[i];
        delete_identity(&self.config, name)?;
        Ok(format!("Identity {name} deleted"))
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

fn select_identity(theme: &ColorfulTheme, config: &GlobalOptions) -> Option<ChannelIdentity> {
    let path = config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
    let local_identities = load_or_create_identities(&path).ok()?;

    let options = local_identities.ids().cloned().collect::<Vec<String>>();
    let profile = FuzzySelect::with_theme(theme)
        .with_prompt("Select identity")
        .items(&options)
        .interact()
        .map(|i| local_identities.identities().skip(i).next().cloned())
        .ok()?;
    profile
}
