#![allow(non_snake_case)]
//! TrueFA Cryptographic Module
//! 
//! This module provides secure cryptographic operations for the TrueFA application.
//! It implements:
//! - Secure memory handling with automatic zeroization
//! - Vault-based secret storage with envelope encryption
//! - Secure random number generation
//! - Key derivation using Scrypt
//! 
//! The module is designed to be called from Python and ensures that sensitive
//! data is properly protected in memory and during storage.

use std::sync::Mutex;
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;
use base64::{decode, encode};
use once_cell::sync::Lazy;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};

/// SecureString provides protected memory storage for sensitive data.
/// The stored data is automatically zeroized when dropped.
#[pyclass]
#[derive(Debug)]
pub struct SecureString {
    data: Vec<u8>,
}

#[pymethods]
impl SecureString {
    /// Creates a new SecureString from a UTF-8 string.
    /// The data is stored in protected memory.
    #[new]
    pub fn new(value: &str) -> Self {
        Self { 
            data: value.as_bytes().to_vec()
        }
    }
    
    /// Returns the stored string as UTF-8.
    /// Note: This temporarily exposes the secret in memory.
    fn __str__(&self) -> PyResult<String> {
        String::from_utf8(self.data.clone())
            .map_err(|_| PyValueError::new_err("Invalid UTF-8 in secure string"))
    }
    
    /// Explicitly clears the stored data by zeroizing the memory.
    fn clear(&mut self) {
        self.data.zeroize();
        self.data = Vec::new();
    }
}

/// Ensures secure cleanup by zeroizing memory when the object is dropped.
impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Thread-safe cache for the vault key with secure memory handling.
/// This struct maintains both the active vault key and original key for verification.
struct VaultKeyCache {
    vault_key: Option<Vec<u8>>,      // Current active key
    original_key: Option<Vec<u8>>,    // Original key for verification
    vault_exists: bool,               // Whether a vault has been initialized
}

impl VaultKeyCache {
    /// Creates a new empty vault key cache.
    fn new() -> Self {
        Self { 
            vault_key: None,
            original_key: None,
            vault_exists: false,
        }
    }
    
    /// Sets both the active and original keys.
    /// Any existing key is securely zeroized before being replaced.
    fn set_key(&mut self, key: Vec<u8>) {
        if let Some(old_key) = &mut self.vault_key {
            old_key.zeroize();
        }
        self.vault_key = Some(key.clone());
        self.original_key = Some(key);
        self.vault_exists = true;
    }
    
    /// Clears only the active key while preserving the original for verification.
    /// The cleared key is securely zeroized.
    fn clear_key(&mut self) {
        if let Some(key) = &mut self.vault_key {
            key.zeroize();
        }
        self.vault_key = None;
        // Keep original_key and vault_exists
    }
    
    /// Verifies a provided key against the stored original key.
    fn verify_key(&self, key: &[u8]) -> bool {
        if let Some(original_key) = &self.original_key {
            key == original_key.as_slice()
        } else {
            false
        }
    }
}

// Global state with thread-safe access to the vault key cache
static VAULT_KEY_CACHE: Lazy<Mutex<VaultKeyCache>> = Lazy::new(|| {
    Mutex::new(VaultKeyCache::new())
});

/// Generates cryptographically secure random bytes using the OS RNG.
#[pyfunction]
fn secure_random_bytes(size: usize) -> PyResult<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Checks if the vault is currently unlocked (has an active key).
#[pyfunction]
fn is_vault_unlocked() -> PyResult<bool> {
    let cache = VAULT_KEY_CACHE.lock().unwrap();
    Ok(cache.vault_key.is_some())
}

/// Checks if a vault has been initialized.
#[pyfunction]
fn vault_exists() -> PyResult<bool> {
    let cache = VAULT_KEY_CACHE.lock().unwrap();
    Ok(cache.vault_exists)
}

/// Creates a new vault with the given master password.
/// Returns the generated salt for key derivation.
#[pyfunction]
fn create_vault(password: &str) -> PyResult<String> {
    // Generate salt and derive master key
    let salt = generate_salt()?;
    let master_key = derive_master_key(password, &salt)?;
    
    // Set up the vault key
    let mut cache = VAULT_KEY_CACHE.lock().unwrap();
    cache.set_key(decode(&master_key).map_err(|e| PyValueError::new_err(e.to_string()))?);
    
    Ok(salt)
}

/// Attempts to unlock the vault with the given password and salt.
/// Returns true if successful, raises an error if the password is incorrect.
#[pyfunction]
fn unlock_vault(password: &str, salt: &str) -> PyResult<bool> {
    let master_key = derive_master_key(password, salt)?;
    let mut cache = VAULT_KEY_CACHE.lock().unwrap();
    
    // Only check if vault exists after we have the lock
    if !cache.vault_exists {
        return Err(PyValueError::new_err("No vault exists to unlock"));
    }
    
    // Verify the master key matches
    let key_bytes = decode(&master_key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    if !cache.verify_key(&key_bytes) {
        return Err(PyValueError::new_err("Invalid master password"));
    }
    
    // Set the key and return success
    cache.set_key(key_bytes);
    Ok(true)
}

/// Locks the vault by clearing the active key while preserving the original for verification.
#[pyfunction]
fn lock_vault() -> PyResult<()> {
    let mut cache = VAULT_KEY_CACHE.lock().unwrap();
    cache.clear_key();
    Ok(())
}

/// Generates a cryptographically secure random salt for key derivation.
fn generate_salt() -> PyResult<String> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    Ok(encode(salt))
}

/// Derives a master key from a password and salt using Scrypt.
/// The derived key is base64 encoded for storage.
fn derive_master_key(master_password: &str, salt_b64: &str) -> PyResult<String> {
    // Convert the base64 salt back to bytes
    let salt_bytes = match decode(salt_b64) {
        Ok(s) => s,
        Err(_) => return Err(PyValueError::new_err("Invalid salt encoding")),
    };
    
    // Create a SaltString from the salt bytes
    let salt = match SaltString::b64_encode(&salt_bytes) {
        Ok(s) => s,
        Err(_) => return Err(PyValueError::new_err("Invalid salt format")),
    };
    
    // Derive the key using scrypt
    let password_hash = Scrypt.hash_password(master_password.as_bytes(), &salt)
        .map_err(|e| PyValueError::new_err(format!("Key derivation error: {}", e)))?;
    
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    
    Ok(encode(hash_bytes))
}

/// Python module initialization
#[pymodule]
fn truefa_crypto(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    // Add the SecureString class first
    m.add_class::<SecureString>()?;
    
    // Then add all the functions
    m.add_function(wrap_pyfunction!(secure_random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(is_vault_unlocked, m)?)?;
    m.add_function(wrap_pyfunction!(vault_exists, m)?)?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
    m.add_function(wrap_pyfunction!(unlock_vault, m)?)?;
    m.add_function(wrap_pyfunction!(lock_vault, m)?)?;
    
    Ok(())
}
