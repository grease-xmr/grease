use crate::interactive::menus::{top_menu, Menu};
use grease_p2p::ChannelIdentity;
use std::fmt::Display;

pub mod formatting;
pub mod menus;
use crate::config::GlobalOptions;
use crate::id_management::{default_id_path, load_or_create_identities};
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
                EXIT => break,
                _ => continue,
            }
        }
        Ok(())
    }

    fn logout(&mut self) {
        self.identity = None;
        println!("Logged out");
    }

    async fn add_profile(&mut self) -> Result<String> {
        let name = dialoguer::Input::<String>::new().with_prompt("Enter new identity name").interact()?;
        let identity = ChannelIdentity::random_with_id(name);

        let path = self.config.config_file.as_ref().cloned().unwrap_or_else(default_id_path);
        let mut local_identities = load_or_create_identities(&path)?;
        if local_identities.contains(identity.id()) {
            return Err(anyhow!("Identity with id {} already exists.", identity.id()));
        }
        println!("Identity created: {identity}");
        local_identities.insert(identity.id().to_string(), identity);
        println!("Saving identities to {}", path.to_str().unwrap_or("[invalid utf-8 path]"));
        local_identities.save(&path)?;
        Ok("Identity added successfully".into())
    }
}

fn print_logo() {
    const LOGO: &str = include_str!("../../../assets/logo.txt");
    println!("{LOGO}");
}

fn handle_response<T: Display>(res: Result<T>) {
    match res {
        Ok(res) => println!("{res}"),
        Err(e) => println!("Error: {}", e),
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
