mod crypto;
mod error;
mod vault;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rpassword::prompt_password;

use crate::crypto::generate_password;
use crate::error::Error;
use crate::vault::{Entry, Vault};

// ─── CLI Definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "passman",
    version,
    about = "A secure local CLI password manager (AES-256-GCM + Argon2id)",
    long_about = None
)]
struct Cli {
    /// Path to the encrypted vault file.
    /// Defaults to ~/.passman/vault.enc
    #[arg(long, global = true)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise a new encrypted vault.
    Init,

    /// Add a new credential entry.
    Add {
        /// Unique label for the entry (e.g. "github", "work-email").
        name: String,
        /// Username or email address.
        username: String,
        /// Optional notes.
        #[arg(long)]
        notes: Option<String>,
        /// Generate a random password instead of prompting.
        #[arg(long)]
        generate: bool,
        /// Length of the generated password (used with --generate).
        #[arg(long, default_value_t = 20)]
        length: usize,
    },

    /// Retrieve a credential entry.
    Get {
        /// Label of the entry to retrieve.
        name: String,
    },

    /// Update an existing credential entry.
    Update {
        /// Label of the entry to update.
        name: String,
        /// New username (leave blank to keep current).
        #[arg(long)]
        username: Option<String>,
        /// New notes.
        #[arg(long)]
        notes: Option<String>,
        /// Generate a new random password instead of prompting.
        #[arg(long)]
        generate: bool,
        /// Length of the generated password (used with --generate).
        #[arg(long, default_value_t = 20)]
        length: usize,
    },

    /// Delete a credential entry.
    Delete {
        /// Label of the entry to delete.
        name: String,
    },

    /// List the names of all stored entries.
    List,

    /// Generate and print a random password without storing it.
    Generate {
        /// Number of characters in the generated password.
        #[arg(short, long, default_value_t = 20)]
        length: usize,
    },
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let vault_path = cli
        .vault
        .unwrap_or_else(Vault::default_path);

    if let Err(e) = run(cli.command, &vault_path) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(command: Command, vault_path: &std::path::Path) -> Result<(), Error> {
    match command {
        // ── Init ──────────────────────────────────────────────────────────────
        Command::Init => {
            let pw = prompt_password("Set master password: ")
                .map_err(|e| Error::Io(e))?;
            let confirm = prompt_password("Confirm master password: ")
                .map_err(|e| Error::Io(e))?;
            if pw != confirm {
                eprintln!("Passwords do not match.");
                std::process::exit(1);
            }
            Vault::init(vault_path, &pw)?;
            println!("✓ Vault initialised at {}", vault_path.display());
        }

        // ── Add ───────────────────────────────────────────────────────────────
        Command::Add {
            name,
            username,
            notes,
            generate,
            length,
        } => {
            let pw = master_password()?;
            let mut v = Vault::load(vault_path, &pw)?;

            let password = if generate {
                let p = generate_password(length);
                println!("Generated password: {p}");
                p
            } else {
                let p = prompt_password("Entry password: ").map_err(Error::Io)?;
                let c = prompt_password("Confirm entry password: ").map_err(Error::Io)?;
                if p != c {
                    eprintln!("Passwords do not match.");
                    std::process::exit(1);
                }
                p
            };

            v.add(Entry {
                name: name.clone(),
                username,
                password,
                notes,
            })?;
            v.save(vault_path, &pw)?;
            println!("✓ Entry '{name}' added.");
        }

        // ── Get ───────────────────────────────────────────────────────────────
        Command::Get { name } => {
            let pw = master_password()?;
            let v = Vault::load(vault_path, &pw)?;
            let e = v
                .find(&name)
                .ok_or_else(|| Error::EntryNotFound(name.clone()))?;
            println!("Name    : {}", e.name);
            println!("Username: {}", e.username);
            println!("Password: {}", e.password);
            if let Some(notes) = &e.notes {
                println!("Notes   : {notes}");
            }
        }

        // ── Update ────────────────────────────────────────────────────────────
        Command::Update {
            name,
            username,
            notes,
            generate,
            length,
        } => {
            let pw = master_password()?;
            let mut v = Vault::load(vault_path, &pw)?;

            let existing = v
                .find(&name)
                .ok_or_else(|| Error::EntryNotFound(name.clone()))?
                .clone();

            let new_username = username.unwrap_or(existing.username);

            let new_password = if generate {
                let p = generate_password(length);
                println!("Generated password: {p}");
                p
            } else {
                let p = prompt_password("New password (Enter to keep current): ")
                    .map_err(Error::Io)?;
                if p.is_empty() {
                    existing.password
                } else {
                    let c = prompt_password("Confirm new password: ").map_err(Error::Io)?;
                    if p != c {
                        eprintln!("Passwords do not match.");
                        std::process::exit(1);
                    }
                    p
                }
            };

            let new_notes = notes.or(existing.notes);

            v.update(Entry {
                name: name.clone(),
                username: new_username,
                password: new_password,
                notes: new_notes,
            })?;
            v.save(vault_path, &pw)?;
            println!("✓ Entry '{name}' updated.");
        }

        // ── Delete ────────────────────────────────────────────────────────────
        Command::Delete { name } => {
            let pw = master_password()?;
            let mut v = Vault::load(vault_path, &pw)?;
            v.delete(&name)?;
            v.save(vault_path, &pw)?;
            println!("✓ Entry '{name}' deleted.");
        }

        // ── List ──────────────────────────────────────────────────────────────
        Command::List => {
            let pw = master_password()?;
            let v = Vault::load(vault_path, &pw)?;
            if v.entries.is_empty() {
                println!("Vault is empty.");
            } else {
                println!("{} entr{}:", v.entries.len(), if v.entries.len() == 1 { "y" } else { "ies" });
                for e in &v.entries {
                    println!("  • {} ({})", e.name, e.username);
                }
            }
        }

        // ── Generate ──────────────────────────────────────────────────────────
        Command::Generate { length } => {
            println!("{}", generate_password(length));
        }
    }
    Ok(())
}

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Prompt for the master password (no echo).
fn master_password() -> Result<String, Error> {
    prompt_password("Master password: ").map_err(Error::Io)
}

