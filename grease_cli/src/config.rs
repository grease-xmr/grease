#![doc = include_str!("../README.md")]

use anyhow::anyhow;
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use clap::{Parser, Subcommand};
use libgrease::cryptography::keys::Curve25519Secret;
use libp2p::Multiaddr;
use monero::Address;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

const DEFAULT_LISTEN_ADDRESS: &str = "/ip4/127.0.0.1/tcp/";

//------------------------------------  DEFAULTS ------------------------------------
pub fn default_listen_address(index: u8) -> Multiaddr {
    Multiaddr::from_str(&format!("{DEFAULT_LISTEN_ADDRESS}{}", 21_000 + index as u16))
        .expect("Invalid default listen address")
}

/// Grease Monero Payment Channels.
///
/// Payment channel management and command-line client for grease.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct CliOptions {
    /// Path to the configuration file. The default is `$HOME/.grease/config.yml`.
    #[arg(long = "config-file", short = 'c')]
    pub config_file: Option<PathBuf>,
    /// P2P identity to use. If omitted, the first record in the identity database is used.
    #[arg(long = "id")]
    pub id_name: Option<String>,
    #[command(subcommand)]
    pub command: CliCommand,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Add, list or delete local peer identities.
    #[command(subcommand, name = "id")]
    Id(IdCommand),
    /// Print a random keypair and quit. The secret key can be used in the `initial_secret` field of the config file.
    #[command(name = "keypair")]
    Keypair,
    /// Run the server.
    #[command(name = "serve", alias = "start")]
    Serve,
}

#[derive(Debug, Subcommand)]
pub enum IdCommand {
    /// Create a new peer identity.
    #[command(name = "new", alias = "create")]
    Create {
        /// The name of the new peer identity. If omitted, a random name is generated.
        name: Option<String>,
    },
    /// List all peer identities.
    #[command(name = "list", alias = "ls")]
    List,
    /// Delete a peer identity.
    #[command(name = "delete", alias = "del", alias = "rm")]
    Delete {
        /// The id of the peer identity to delete.
        id: String,
    },
}

/// Configuration for the CLI.
///
/// ## Security Warning
///
/// The `initial_secret` field can be stored in different modes:
/// - **Encrypted mode**: Protected with a password using Argon2id + ChaCha20-Poly1305
/// - **Plaintext mode**: Stored as a hex string (for development/testing only)
///
/// When loading a config with an encrypted secret, use [`GlobalOptions::decrypt_secret`]
/// to decrypt it with the user's password.
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct GlobalOptions {
    /// The path to the configuration file. If not set, defaults to `$HOME/.grease/config.yml`.
    pub base_path: Option<PathBuf>,
    /// The path to the identity database. If not set, defaults to `$HOME/.grease/identities.yml`.
    pub identities_file: Option<PathBuf>,
    /// The default identity to use when creating new channels.
    pub preferred_identity: Option<String>,
    /// The address other parties can use to contact this identity on the internet.
    pub server_address: Option<Multiaddr>,
    /// The public key of the Key Escrow Service (KES).
    pub kes_public_key: Option<String>,
    /// A name, or label that will be inserted into every channel you are part of.
    /// Make it descriptive and unique.
    pub user_label: Option<String>,
    /// The initial secret key for the key manager.
    ///
    /// This can be stored encrypted (with password protection) or in plaintext.
    /// Use [`PasswordProtectedSecret::encrypt`] to encrypt a secret with a password,
    /// or [`PasswordProtectedSecret::plaintext`] for development/testing (with warning).
    #[serde(default)]
    pub initial_secret: Option<PasswordProtectedSecret>,
    /// The folder where channels are stored.
    /// `channel_storage_directory` can be a relative or absolute path. If relative, it is a subdirectory of the
    /// `base_path`.
    pub channel_storage_directory: Option<PathBuf>,
    /// The address of the wallet that will receive funds on channel closures.
    pub refund_address: Option<Address>,
}

impl GlobalOptions {
    /// Loads global configuration options from a YAML file.
    ///
    /// If a path is provided, attempts to load the configuration from that file; otherwise, uses the default configuration path.
    /// Returns an error if the file does not exist or cannot be parsed.
    pub fn load_config<F: AsRef<Path>>(path: Option<F>) -> Result<Self, anyhow::Error> {
        let path = path.map(|p| p.as_ref().to_path_buf()).unwrap_or_else(default_config_path);
        if !path.exists() {
            return Err(anyhow!("Configuration file not found: {}", path.display()));
        }
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let config = serde_yml::from_reader(reader)?;
        Ok(config)
    }

    /// Returns a clone of the configured server listening address, if set.
    pub fn server_address(&self) -> Option<Multiaddr> {
        self.server_address.clone()
    }

    /// Returns a clone of the configured Curve25519 public key, if set.
    pub fn kes_public_key(&self) -> Option<String> {
        self.kes_public_key.clone()
    }

    /// Returns the address to which channel refunds will be sent.
    pub fn refund_address(&self) -> Option<Address> {
        self.refund_address
    }

    /// Returns the optional user label configured for channels.
    pub fn user_label(&self) -> Option<String> {
        self.user_label.clone()
    }

    /// The base path for grease configuration files and stored state, such as identities and channels.
    pub fn base_path(&self) -> PathBuf {
        self.base_path.clone().unwrap_or_else(|| {
            let mut path = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
            path.push(".grease");
            path
        })
    }

    /// Returns the absolute path to the channel storage directory.
    ///
    /// It is derived from `base_path` and `channel_storage_directory`.
    /// If `channel_storage_directory` is relative, it is joined with `base_path`.
    /// If `channel_storage_directory` is absolute, it is returned as is.
    ///
    /// If `channel_storage_directory` is not set, it defaults to `{base_path}/channels`.
    pub fn channel_directory(&self) -> PathBuf {
        let channel_dir = self.channel_storage_directory.as_ref().cloned().unwrap_or_else(|| "channels".into());
        if channel_dir.is_relative() {
            self.base_path().join(channel_dir)
        } else {
            channel_dir
        }
    }

    /// Returns the initial secret, decrypting it if necessary.
    ///
    /// # Arguments
    /// * `password` - The password to decrypt the secret. If the secret is stored in plaintext,
    ///   this parameter is ignored but a warning is logged.
    ///
    /// # Returns
    /// The decrypted secret key, or `None` if no secret is configured.
    ///
    /// # Errors
    /// Returns an error if the password is incorrect or decryption fails.
    pub fn initial_secret(&self, password: &str) -> Result<Option<Curve25519Secret>, PasswordProtectedSecretError> {
        match &self.initial_secret {
            Some(protected) => Ok(Some(protected.decrypt(password)?)),
            None => Ok(None),
        }
    }

    /// Returns the initial secret if it's stored in plaintext (for development/testing).
    ///
    /// # Returns
    /// The secret key if stored in plaintext, `None` otherwise.
    ///
    /// # Warning
    /// This should only be used for development. Production configs should use password protection.
    pub fn initial_secret_plaintext(&self) -> Option<Curve25519Secret> {
        self.initial_secret.as_ref().and_then(|p| p.plaintext_secret())
    }

    /// Check if the initial secret requires a password to decrypt.
    pub fn initial_secret_needs_password(&self) -> bool {
        self.initial_secret.as_ref().is_some_and(|p| p.is_encrypted())
    }
}

/// Returns the default path to the configuration file, typically `$HOME/.grease/config.yml`.
///
/// If the home directory cannot be determined, the path defaults to `./.grease/config.yml`.
pub fn default_config_path() -> PathBuf {
    let mut home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.push(".grease");
    home.push("config.yml");
    home
}

// ======================= PasswordProtectedSecret =======================

/// Errors that can occur when working with password-protected secrets.
#[derive(Debug, Error)]
pub enum PasswordProtectedSecretError {
    #[error("Decryption failed: incorrect password or corrupted data")]
    DecryptionFailed,
    #[error("Invalid hex encoding: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Invalid key format: {0}")]
    KeyError(#[from] libgrease::cryptography::keys::KeyError),
    #[error("Argon2 error: {0}")]
    Argon2Error(String),
}

/// A password-protected secret for config storage.
///
/// Supports two storage modes:
/// - **Encrypted**: Protected with Argon2id key derivation + ChaCha20-Poly1305 encryption
/// - **Plaintext**: Stored as hex (for development/testing only, with warning)
///
/// ## YAML Format
///
/// Encrypted format:
/// ```yaml
/// initial_secret:
///   encrypted: true
///   salt: "base64_salt"
///   nonce: "hex_nonce"
///   ciphertext: "hex_ciphertext"
/// ```
///
/// Plaintext format (development only):
/// ```yaml
/// initial_secret:
///   encrypted: false
///   # WARNING: Secret stored in plaintext! For development only.
///   plaintext: "hex_encoded_secret"
/// ```
///
/// Legacy format (auto-detected, will be migrated on save):
/// ```yaml
/// initial_secret: "hex_encoded_secret"
/// ```
#[derive(Clone, Debug)]
pub enum PasswordProtectedSecret {
    /// Encrypted secret with Argon2id + ChaCha20-Poly1305
    Encrypted {
        /// Argon2 salt (PHC string format)
        salt: String,
        /// ChaCha20-Poly1305 nonce (12 bytes, hex-encoded)
        nonce: [u8; 12],
        /// Encrypted secret + auth tag (hex-encoded)
        ciphertext: Vec<u8>,
    },
    /// Plaintext secret (development only)
    Plaintext(Curve25519Secret),
}

impl PasswordProtectedSecret {
    /// Encrypt a secret with a password.
    ///
    /// Uses Argon2id for key derivation and ChaCha20-Poly1305 for encryption.
    pub fn encrypt(secret: &Curve25519Secret, password: &str) -> Result<Self, PasswordProtectedSecretError> {
        // Generate random salt
        let salt = SaltString::generate(&mut OsRng);

        // Derive key using Argon2id
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| PasswordProtectedSecretError::Argon2Error(e.to_string()))?;

        // Extract the hash output (32 bytes for ChaCha20 key)
        let hash_output = password_hash
            .hash
            .ok_or_else(|| PasswordProtectedSecretError::Argon2Error("No hash output from Argon2".to_string()))?;
        let key_bytes = hash_output.as_bytes();

        // Create cipher and generate random nonce
        let cipher = ChaCha20Poly1305::new_from_slice(key_bytes)
            .map_err(|e| PasswordProtectedSecretError::Argon2Error(format!("Key creation failed: {e}")))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt the secret
        let plaintext = secret.as_hex();
        let ciphertext = cipher
            .encrypt((&nonce).into(), plaintext.as_bytes())
            .map_err(|e| PasswordProtectedSecretError::Argon2Error(format!("Encrypt failed: {e}")))?;

        Ok(Self::Encrypted { salt: salt.to_string(), nonce, ciphertext })
    }

    /// Create a plaintext (unencrypted) secret for development/testing.
    ///
    /// ## Security Warning
    ///
    /// This stores the secret WITHOUT encryption. Only use for development!
    pub fn plaintext(secret: Curve25519Secret) -> Self {
        log::warn!("Storing secret in plaintext. This should only be used for development!");
        Self::Plaintext(secret)
    }

    /// Decrypt the secret with a password.
    ///
    /// For plaintext secrets, the password is ignored but a warning is logged.
    pub fn decrypt(&self, password: &str) -> Result<Curve25519Secret, PasswordProtectedSecretError> {
        match self {
            Self::Plaintext(secret) => {
                log::warn!("Loading plaintext secret from config. Consider using password protection.");
                Ok(secret.clone())
            }
            Self::Encrypted { salt, nonce, ciphertext } => {
                // Parse salt and derive key
                let salt = SaltString::from_b64(salt)
                    .map_err(|e| PasswordProtectedSecretError::Argon2Error(format!("Invalid salt: {e}")))?;
                let argon2 = Argon2::default();
                let password_hash = argon2
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|e| PasswordProtectedSecretError::Argon2Error(e.to_string()))?;

                let hash_output = password_hash.hash.ok_or_else(|| {
                    PasswordProtectedSecretError::Argon2Error("No hash output from Argon2".to_string())
                })?;
                let key_bytes = hash_output.as_bytes();

                // Decrypt
                let cipher = ChaCha20Poly1305::new_from_slice(key_bytes)
                    .map_err(|e| PasswordProtectedSecretError::Argon2Error(format!("Key creation failed: {e}")))?;
                let plaintext_bytes = cipher
                    .decrypt(nonce.into(), ciphertext.as_slice())
                    .map_err(|_| PasswordProtectedSecretError::DecryptionFailed)?;

                let hex_str =
                    String::from_utf8(plaintext_bytes).map_err(|_| PasswordProtectedSecretError::DecryptionFailed)?;
                let secret = Curve25519Secret::from_hex(&hex_str)?;
                Ok(secret)
            }
        }
    }

    /// Check if this secret is encrypted (requires password to decrypt).
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted { .. })
    }

    /// Get the plaintext secret if stored unencrypted.
    pub fn plaintext_secret(&self) -> Option<Curve25519Secret> {
        match self {
            Self::Plaintext(secret) => Some(secret.clone()),
            Self::Encrypted { .. } => None,
        }
    }
}

/// Intermediate struct for serde serialization/deserialization
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PasswordProtectedSecretSerde {
    /// Legacy format: just a hex string
    LegacyHex(String),
    /// Structured format with encryption flag
    Structured {
        encrypted: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        salt: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ciphertext: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
    },
}

impl Serialize for PasswordProtectedSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Plaintext(secret) => {
                let serde_val = PasswordProtectedSecretSerde::Structured {
                    encrypted: false,
                    salt: None,
                    nonce: None,
                    ciphertext: None,
                    plaintext: Some(secret.as_hex()),
                };
                serde_val.serialize(serializer)
            }
            Self::Encrypted { salt, nonce, ciphertext } => {
                let serde_val = PasswordProtectedSecretSerde::Structured {
                    encrypted: true,
                    salt: Some(salt.clone()),
                    nonce: Some(hex::encode(nonce)),
                    ciphertext: Some(hex::encode(ciphertext)),
                    plaintext: None,
                };
                serde_val.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for PasswordProtectedSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serde_val = PasswordProtectedSecretSerde::deserialize(deserializer)?;

        match serde_val {
            PasswordProtectedSecretSerde::LegacyHex(hex_str) => {
                // Legacy format: just a hex string, treat as plaintext
                log::warn!(
                    "Loading legacy plaintext secret from config. \
                     Consider migrating to password-protected format."
                );
                let secret = Curve25519Secret::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
                Ok(Self::Plaintext(secret))
            }
            PasswordProtectedSecretSerde::Structured { encrypted, salt, nonce, ciphertext, plaintext } => {
                if encrypted {
                    let salt = salt.ok_or_else(|| serde::de::Error::missing_field("salt"))?;
                    let nonce_hex = nonce.ok_or_else(|| serde::de::Error::missing_field("nonce"))?;
                    let ciphertext_hex = ciphertext.ok_or_else(|| serde::de::Error::missing_field("ciphertext"))?;

                    let nonce_bytes = hex::decode(&nonce_hex).map_err(serde::de::Error::custom)?;
                    let nonce: [u8; 12] =
                        nonce_bytes.try_into().map_err(|_| serde::de::Error::custom("nonce must be 12 bytes"))?;
                    let ciphertext = hex::decode(&ciphertext_hex).map_err(serde::de::Error::custom)?;

                    Ok(Self::Encrypted { salt, nonce, ciphertext })
                } else {
                    let plaintext_hex = plaintext.ok_or_else(|| serde::de::Error::missing_field("plaintext"))?;
                    let secret = Curve25519Secret::from_hex(&plaintext_hex).map_err(serde::de::Error::custom)?;
                    Ok(Self::Plaintext(secret))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_protected_encrypt_decrypt_roundtrip() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let password = "test_password_123";

        let protected = PasswordProtectedSecret::encrypt(&secret, password).unwrap();
        assert!(protected.is_encrypted());

        let decrypted = protected.decrypt(password).unwrap();
        assert_eq!(secret.as_hex(), decrypted.as_hex());
    }

    #[test]
    fn password_protected_wrong_password_fails() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let password = "correct_password";

        let protected = PasswordProtectedSecret::encrypt(&secret, password).unwrap();
        let result = protected.decrypt("wrong_password");
        assert!(matches!(result, Err(PasswordProtectedSecretError::DecryptionFailed)));
    }

    #[test]
    fn password_protected_plaintext_roundtrip() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let protected = PasswordProtectedSecret::plaintext(secret.clone());

        assert!(!protected.is_encrypted());
        assert!(protected.plaintext_secret().is_some());

        // Decrypt works with any password for plaintext
        let decrypted = protected.decrypt("any_password").unwrap();
        assert_eq!(secret.as_hex(), decrypted.as_hex());
    }

    #[test]
    fn password_protected_serde_encrypted_roundtrip() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let password = "test_password";
        let protected = PasswordProtectedSecret::encrypt(&secret, password).unwrap();

        let yaml = serde_yml::to_string(&protected).unwrap();
        assert!(yaml.contains("encrypted: true"));
        assert!(yaml.contains("salt:"));
        assert!(yaml.contains("nonce:"));
        assert!(yaml.contains("ciphertext:"));

        let loaded: PasswordProtectedSecret = serde_yml::from_str(&yaml).unwrap();
        let decrypted = loaded.decrypt(password).unwrap();
        assert_eq!(secret.as_hex(), decrypted.as_hex());
    }

    #[test]
    fn password_protected_serde_plaintext_roundtrip() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let protected = PasswordProtectedSecret::plaintext(secret.clone());

        let yaml = serde_yml::to_string(&protected).unwrap();
        assert!(yaml.contains("encrypted: false"));
        assert!(yaml.contains("plaintext:"));

        let loaded: PasswordProtectedSecret = serde_yml::from_str(&yaml).unwrap();
        let decrypted = loaded.decrypt("").unwrap();
        assert_eq!(secret.as_hex(), decrypted.as_hex());
    }

    #[test]
    fn password_protected_serde_legacy_format() {
        let secret = Curve25519Secret::random(&mut OsRng);
        let hex = secret.as_hex();

        // Legacy format is just a quoted hex string
        let yaml = format!("\"{hex}\"");
        let loaded: PasswordProtectedSecret = serde_yml::from_str(&yaml).unwrap();
        let decrypted = loaded.decrypt("").unwrap();
        assert_eq!(secret.as_hex(), decrypted.as_hex());
    }
}
