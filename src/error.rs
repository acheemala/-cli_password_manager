use std::fmt;

/// All errors that can occur in passman.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Argon2(argon2::Error),
    /// Decryption / authentication failure (wrong password or corrupted data).
    Crypto,
    /// The vault file does not exist yet.
    VaultNotFound,
    /// An entry with the requested name does not exist.
    EntryNotFound(String),
    /// An entry with the given name already exists.
    EntryAlreadyExists(String),
    /// The vault has already been initialised.
    VaultAlreadyExists,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Json(e) => write!(f, "Serialisation error: {e}"),
            Error::Argon2(e) => write!(f, "Key-derivation error: {e}"),
            Error::Crypto => write!(
                f,
                "Decryption failed – wrong master password or corrupted vault."
            ),
            Error::VaultNotFound => write!(
                f,
                "Vault not found. Run `passman init` to create one."
            ),
            Error::EntryNotFound(name) => {
                write!(f, "No entry named '{name}' found in the vault.")
            }
            Error::EntryAlreadyExists(name) => {
                write!(f, "An entry named '{name}' already exists – use `update` instead.")
            }
            Error::VaultAlreadyExists => write!(
                f,
                "A vault already exists. Delete it manually to re-initialise."
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2(e)
    }
}
