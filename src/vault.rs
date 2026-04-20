use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, derive_key, encrypt, random_bytes, NONCE_LEN, SALT_LEN};
use crate::error::Error;

// ─── Data Structures ──────────────────────────────────────────────────────────

/// A single credential record stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Unique name / label for this credential (e.g. "github").
    pub name: String,
    /// Username or email address.
    pub username: String,
    /// Plaintext password (only in memory; never written to disk unencrypted).
    pub password: String,
    /// Optional free-form notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// The in-memory plaintext vault containing all entries.
#[derive(Debug, Serialize, Deserialize)]
struct PlainVault {
    entries: Vec<Entry>,
}

/// The on-disk representation of the encrypted vault.
#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    /// Format version for forward-compatibility.
    version: u32,
    /// Base64-encoded Argon2 salt.
    salt: String,
    /// Base64-encoded AES-GCM nonce.
    nonce: String,
    /// Base64-encoded ciphertext (includes GCM authentication tag).
    ciphertext: String,
}

// ─── Public Vault API ─────────────────────────────────────────────────────────

/// High-level vault handle.
pub struct Vault {
    pub entries: Vec<Entry>,
}

impl Vault {
    // ── Persistence ───────────────────────────────────────────────────────────

    /// Default vault file path: `~/.passman/vault.enc`.
    pub fn default_path() -> PathBuf {
        let home = dirs_from_env();
        home.join(".passman").join("vault.enc")
    }

    /// Initialise a brand-new vault at `path` protected by `master_password`.
    ///
    /// Fails if the vault file already exists.
    pub fn init(path: &Path, master_password: &str) -> Result<(), Error> {
        if path.exists() {
            return Err(Error::VaultAlreadyExists);
        }
        let vault = Vault { entries: vec![] };
        vault.save(path, master_password)
    }

    /// Load and decrypt the vault from `path` using `master_password`.
    pub fn load(path: &Path, master_password: &str) -> Result<Self, Error> {
        if !path.exists() {
            return Err(Error::VaultNotFound);
        }

        let raw = fs::read_to_string(path)?;
        let file: VaultFile = serde_json::from_str(&raw)?;

        let salt_bytes = B64.decode(&file.salt).map_err(|_| Error::Crypto)?;
        let nonce_bytes: [u8; NONCE_LEN] = B64
            .decode(&file.nonce)
            .map_err(|_| Error::Crypto)?
            .try_into()
            .map_err(|_| Error::Crypto)?;
        let ciphertext = B64.decode(&file.ciphertext).map_err(|_| Error::Crypto)?;

        let key = derive_key(master_password, &salt_bytes)?;
        let plaintext = decrypt(&key, &ciphertext, &nonce_bytes)?;

        let plain: PlainVault = serde_json::from_slice(&plaintext)?;
        Ok(Vault {
            entries: plain.entries,
        })
    }

    /// Encrypt and persist the vault to `path`.
    pub fn save(&self, path: &Path, master_password: &str) -> Result<(), Error> {
        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let plain = PlainVault {
            entries: self.entries.clone(),
        };
        let plaintext = serde_json::to_vec(&plain)?;

        let salt: [u8; SALT_LEN] = random_bytes();
        let key = derive_key(master_password, &salt)?;
        let (ciphertext, nonce) = encrypt(&key, &plaintext)?;

        let file = VaultFile {
            version: 1,
            salt: B64.encode(salt),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(&ciphertext),
        };

        let json = serde_json::to_string_pretty(&file)?;
        fs::write(path, json)?;
        Ok(())
    }

    // ── Entry Operations ──────────────────────────────────────────────────────

    /// Add a new entry.  Returns `Err` if an entry with the same name exists.
    pub fn add(&mut self, entry: Entry) -> Result<(), Error> {
        if self.find(&entry.name).is_some() {
            return Err(Error::EntryAlreadyExists(entry.name.clone()));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Look up an entry by name (case-insensitive).
    pub fn find(&self, name: &str) -> Option<&Entry> {
        let lower = name.to_lowercase();
        self.entries.iter().find(|e| e.name.to_lowercase() == lower)
    }

    /// Update an existing entry.
    pub fn update(&mut self, entry: Entry) -> Result<(), Error> {
        let lower = entry.name.to_lowercase();
        let pos = self
            .entries
            .iter()
            .position(|e| e.name.to_lowercase() == lower)
            .ok_or_else(|| Error::EntryNotFound(entry.name.clone()))?;
        self.entries[pos] = entry;
        Ok(())
    }

    /// Delete an entry by name.  Returns the removed entry.
    pub fn delete(&mut self, name: &str) -> Result<Entry, Error> {
        let lower = name.to_lowercase();
        let pos = self
            .entries
            .iter()
            .position(|e| e.name.to_lowercase() == lower)
            .ok_or_else(|| Error::EntryNotFound(name.to_owned()))?;
        Ok(self.entries.remove(pos))
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Return the user's home directory, falling back to `/tmp` if unset.
fn dirs_from_env() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn temp_vault_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("vault.enc");
        (dir, path)
    }

    #[test]
    fn init_and_reload() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "masterpass").expect("init");
        let vault = Vault::load(&path, "masterpass").expect("load");
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn add_get_delete_round_trip() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "pw").expect("init");
        let mut vault = Vault::load(&path, "pw").unwrap();

        vault
            .add(Entry {
                name: "github".into(),
                username: "alice".into(),
                password: "s3cret".into(),
                notes: None,
            })
            .unwrap();
        vault.save(&path, "pw").unwrap();

        let vault2 = Vault::load(&path, "pw").unwrap();
        let e = vault2.find("github").expect("entry present");
        assert_eq!(e.username, "alice");
        assert_eq!(e.password, "s3cret");

        let mut vault3 = Vault::load(&path, "pw").unwrap();
        vault3.delete("github").unwrap();
        vault3.save(&path, "pw").unwrap();

        let vault4 = Vault::load(&path, "pw").unwrap();
        assert!(vault4.find("github").is_none());
    }

    #[test]
    fn wrong_password_fails() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "correct").unwrap();
        assert!(Vault::load(&path, "wrong").is_err());
    }

    #[test]
    fn duplicate_entry_rejected() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "pw").unwrap();
        let mut vault = Vault::load(&path, "pw").unwrap();
        let e = || Entry {
            name: "site".into(),
            username: "bob".into(),
            password: "abc".into(),
            notes: None,
        };
        vault.add(e()).unwrap();
        assert!(matches!(vault.add(e()), Err(Error::EntryAlreadyExists(_))));
    }

    #[test]
    fn update_entry() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "pw").unwrap();
        let mut vault = Vault::load(&path, "pw").unwrap();
        vault
            .add(Entry {
                name: "site".into(),
                username: "bob".into(),
                password: "old".into(),
                notes: None,
            })
            .unwrap();
        vault
            .update(Entry {
                name: "site".into(),
                username: "bob".into(),
                password: "new".into(),
                notes: Some("updated".into()),
            })
            .unwrap();
        vault.save(&path, "pw").unwrap();
        let v2 = Vault::load(&path, "pw").unwrap();
        assert_eq!(v2.find("site").unwrap().password, "new");
    }

    #[test]
    fn init_twice_fails() {
        let (_dir, path) = temp_vault_path();
        Vault::init(&path, "pw").unwrap();
        assert!(matches!(Vault::init(&path, "pw"), Err(Error::VaultAlreadyExists)));
    }

    #[test]
    fn load_nonexistent_vault() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("no_vault.enc");
        assert!(matches!(Vault::load(&path, "pw"), Err(Error::VaultNotFound)));
    }
}
