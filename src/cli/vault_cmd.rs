use std::path::Path;

use anyhow::{bail, Context, Result};

use wardn::Vault;

use super::VaultCommands;

/// Read passphrase from WARDN_PASSPHRASE env var or prompt interactively.
fn read_passphrase(prompt: &str) -> Result<String> {
    if let Ok(pass) = std::env::var("WARDN_PASSPHRASE") {
        tracing::warn!("using passphrase from WARDN_PASSPHRASE env var — not recommended for production");
        return Ok(pass);
    }
    rpassword::prompt_password(prompt).context("failed to read passphrase")
}

/// Read a secret value from WARDN_VALUE env var or prompt interactively.
fn read_value(prompt: &str) -> Result<String> {
    if let Ok(val) = std::env::var("WARDN_VALUE") {
        return Ok(val);
    }
    rpassword::prompt_password(prompt).context("failed to read value")
}

pub fn run(cmd: &VaultCommands, vault_path: &Path) -> Result<()> {
    match cmd {
        VaultCommands::Create => {
            if vault_path.exists() {
                bail!("vault already exists at {}", vault_path.display());
            }

            if let Some(parent) = vault_path.parent() {
                std::fs::create_dir_all(parent)
                    .context("failed to create vault directory")?;
            }

            let passphrase = read_passphrase("Passphrase: ")?;
            let confirm = read_passphrase("Confirm passphrase: ")?;

            if passphrase != confirm {
                bail!("passphrases do not match");
            }

            if passphrase.is_empty() {
                bail!("passphrase cannot be empty");
            }

            Vault::create(vault_path, &passphrase)?;
            println!("vault created at {}", vault_path.display());
        }

        VaultCommands::Set { key } => {
            let passphrase = read_passphrase("Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let value = read_value(&format!("Value for {key}: "))?;
            if value.is_empty() {
                bail!("value cannot be empty");
            }

            vault.set(key, &value)?;
            println!("stored {key}");
        }

        VaultCommands::Get { key, agent } => {
            let passphrase = read_passphrase("Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let placeholder = vault.get_placeholder(key, agent)?;
            println!("{}", placeholder.as_str());
        }

        VaultCommands::List => {
            let passphrase = read_passphrase("Passphrase: ")?;
            let vault = Vault::open(vault_path, &passphrase)?;

            let creds = vault.list();
            if creds.is_empty() {
                println!("vault is empty");
                return Ok(());
            }

            println!(
                "{:<24} {:<20} {:<20} {:<10} CREATED",
                "NAME", "AGENTS", "DOMAINS", "RATE LIMIT"
            );
            println!("{}", "-".repeat(90));

            for info in &creds {
                let agents = if info.allowed_agents.is_empty() {
                    "*".to_string()
                } else {
                    info.allowed_agents.join(", ")
                };
                let domains = if info.allowed_domains.is_empty() {
                    "*".to_string()
                } else {
                    info.allowed_domains.join(", ")
                };
                let rl = if info.has_rate_limit { "yes" } else { "no" };
                let created = &info.created_at[..10]; // date only

                println!("{:<24} {:<20} {:<20} {:<10} {}", info.name, agents, domains, rl, created);
            }
        }

        VaultCommands::Rotate { key } => {
            let passphrase = read_passphrase("Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            let new_value = read_value(&format!("New value for {key}: "))?;
            if new_value.is_empty() {
                bail!("value cannot be empty");
            }

            vault.rotate(key, &new_value)?;
            println!("rotated {key} — existing placeholders unchanged");
        }

        VaultCommands::Remove { key } => {
            let passphrase = read_passphrase("Passphrase: ")?;
            let mut vault = Vault::open(vault_path, &passphrase)?;

            vault.remove(key)?;
            println!("removed {key}");
        }
    }

    Ok(())
}
