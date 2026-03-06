use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::Error;

/// Length of an AES-GCM nonce in bytes (96 bits).
pub const NONCE_LEN: usize = 12;
/// Length of an Argon2 salt in bytes.
pub const SALT_LEN: usize = 32;
/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Character set used for generated passwords.
const CHARSET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

// ─── Key Derivation ────────────────────────────────────────────────────────────

/// Derive a 256-bit key from `password` and `salt` using Argon2id.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], Error> {
    use argon2::Argon2;
    let mut key = [0u8; KEY_LEN];
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}

// ─── Random Byte Generation ────────────────────────────────────────────────────

/// Generate cryptographically secure random bytes.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let rng = SystemRandom::new();
    let mut buf = [0u8; N];
    rng.fill(&mut buf).expect("SystemRandom failed");
    buf
}

// ─── AES-256-GCM ──────────────────────────────────────────────────────────────

/// Encrypt `plaintext` with AES-256-GCM.
///
/// Returns `(ciphertext_with_tag, nonce)`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), Error> {
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Crypto)?;
    let sealing = LessSafeKey::new(unbound);

    let mut buf = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| Error::Crypto)?;

    Ok((buf, nonce_bytes))
}

/// Decrypt `ciphertext` (ciphertext + 16-byte GCM tag) with AES-256-GCM.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce_bytes: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let unbound = UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Crypto)?;
    let opening = LessSafeKey::new(unbound);

    let mut buf = ciphertext.to_vec();
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| Error::Crypto)?;

    Ok(plaintext.to_vec())
}

// ─── Password Generator ────────────────────────────────────────────────────────

/// Generate a random password of the given length using a secure RNG.
pub fn generate_password(length: usize) -> String {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; length];
    rng.fill(&mut buf).expect("SystemRandom failed");
    buf.iter()
        .map(|&b| CHARSET[b as usize % CHARSET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let password = "test-master-password";
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key(password, &salt).expect("derive_key failed");

        let plaintext = b"super secret data";
        let (ciphertext, nonce) = encrypt(&key, plaintext).expect("encrypt failed");

        assert_ne!(ciphertext, plaintext, "ciphertext must not equal plaintext");

        let decrypted = decrypt(&key, &ciphertext, &nonce).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let salt = random_bytes::<SALT_LEN>();
        let key_a = derive_key("correct-password", &salt).unwrap();
        let key_b = derive_key("wrong-password", &salt).unwrap();

        let (ciphertext, nonce) = encrypt(&key_a, b"secret").unwrap();
        assert!(decrypt(&key_b, &ciphertext, &nonce).is_err());
    }

    #[test]
    fn generated_password_length() {
        for len in [8, 16, 32, 64] {
            let pwd = generate_password(len);
            assert_eq!(pwd.chars().count(), len);
        }
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let salt_a = random_bytes::<SALT_LEN>();
        let salt_b = random_bytes::<SALT_LEN>();
        let key_a = derive_key("password", &salt_a).unwrap();
        let key_b = derive_key("password", &salt_b).unwrap();
        assert_ne!(key_a, key_b);
    }
}
