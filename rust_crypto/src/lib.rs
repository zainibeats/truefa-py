#![allow(non_snake_case)]
//! TrueFA Rust Cryptography Module
//! 
//! High-performance, memory-safe implementation of cryptographic operations
//! for the TrueFA application. Features include:
//! - Automatic memory zeroization for sensitive data
//! - Envelope encryption with master key protection
//! - Secure random generation using OS entropy sources
//! - Scrypt key derivation for vault password handling
//! - AES-256-GCM authenticated encryption
//! 
//! This module exposes both Python bindings for direct integration
//! and C-compatible functions for FFI access from other languages.

use std::sync::Mutex;
use pyo3::{prelude::*, exceptions::PyValueError};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;
use base64;
use once_cell::sync::Lazy;
use scrypt::{password_hash::{PasswordHasher, SaltString}, Scrypt};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

// Define C types for FFI
#[allow(non_camel_case_types)]
type c_bool = bool;

/// Memory-protected string with automatic zeroization on drop.
/// Prevents sensitive data exposure through memory dumps or leaks.
#[pyclass]
#[derive(Debug)]
pub struct SecureString {
    data: Vec<u8>,
}

#[pymethods]
impl SecureString {
    /// Creates a new SecureString from a UTF-8 string.
    /// Stores data in protected memory when available.
    #[new]
    pub fn new(value: &str) -> Self {
        Self { 
            data: value.as_bytes().to_vec()
        }
    }
    
    /// Retrieves stored data as UTF-8 string.
    /// Note: Temporarily exposes the secret in memory.
    fn __str__(&self) -> PyResult<String> {
        String::from_utf8(self.data.clone())
            .map_err(|_| PyValueError::new_err("Invalid UTF-8 in secure string"))
    }
    
    /// Explicitly zeroizes memory and clears the stored data.
    fn clear(&mut self) {
        self.data.zeroize();
        self.data = Vec::new();
    }
}

/// Ensures secure cleanup by zeroizing memory when dropped.
impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Thread-safe cache for vault encryption keys with secure memory handling.
struct VaultKeyCache {
    vault_key: Option<Vec<u8>>,      // Active encryption key
    original_key: Option<Vec<u8>>,    // Original key for verification
    vault_exists: bool,               // Vault initialization state
}

impl VaultKeyCache {
    /// Creates a new empty key cache with no active vault.
    fn new() -> Self {
        Self { 
            vault_key: None,
            original_key: None,
            vault_exists: false,
        }
    }
    
    /// Sets both active and verification keys, zeroizing any existing key.
    fn set_key(&mut self, key: Vec<u8>) {
        if let Some(old_key) = &mut self.vault_key {
            old_key.zeroize();
        }
        self.vault_key = Some(key.clone());
        self.original_key = Some(key);
        self.vault_exists = true;
    }
    
    /// Securely clears the active key while preserving verification key.
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
    cache.set_key(base64::decode(&master_key).map_err(|e| PyValueError::new_err(e.to_string()))?);
    
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
    let key_bytes = base64::decode(&master_key).map_err(|e| PyValueError::new_err(e.to_string()))?;
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
#[pyfunction]
fn generate_salt() -> PyResult<String> {
    let mut salt = vec![0u8; 16];
    OsRng.fill_bytes(&mut salt);
    Ok(base64::encode(salt))
}

/// Derives a master key from a password and salt using Scrypt.
/// The derived key is base64 encoded for storage.
#[pyfunction]
fn derive_master_key(master_password: &str, salt_b64: &str) -> PyResult<String> {
    // Convert the base64 salt back to bytes
    let salt_bytes = match base64::decode(salt_b64) {
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
    
    Ok(base64::encode(hash_bytes))
}

/// Encrypts the master key using the vault key.
/// The vault key must be unlocked for this operation to succeed.
#[pyfunction]
fn encrypt_master_key(master_key_b64: &str) -> PyResult<String> {
    let cache = VAULT_KEY_CACHE.lock().unwrap();
    
    // Check if vault is unlocked
    if cache.vault_key.is_none() {
        return Err(PyValueError::new_err("Vault is locked, cannot encrypt master key"));
    }
    
    // Decode the master key from base64
    let master_key = base64::decode(master_key_b64)
        .map_err(|e| PyValueError::new_err(format!("Invalid master key encoding: {}", e)))?;
    
    // Create a secure random nonce
    let mut nonce_bytes = [0u8; 12]; // AES-GCM requires a 12-byte nonce
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Use the vault key to encrypt the master key
    let cipher = Aes256Gcm::new_from_slice(cache.vault_key.as_ref().unwrap())
        .map_err(|e| PyValueError::new_err(format!("Cipher initialization error: {}", e)))?;
    
    // Encrypt the master key
    let ciphertext = cipher.encrypt(nonce, master_key.as_ref())
        .map_err(|e| PyValueError::new_err(format!("Encryption error: {}", e)))?;
    
    // Concatenate the nonce and ciphertext and encode as base64
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(base64::encode(result))
}

/// Decrypts the encrypted master key using the vault key.
/// The vault key must be unlocked for this operation to succeed.
#[pyfunction]
fn decrypt_master_key(encrypted_key_b64: &str) -> PyResult<String> {
    let cache = VAULT_KEY_CACHE.lock().unwrap();
    
    // Check if vault is unlocked
    if cache.vault_key.is_none() {
        return Err(PyValueError::new_err("Vault is locked, cannot decrypt master key"));
    }
    
    // Decode the encrypted key from base64
    let encrypted_data = base64::decode(encrypted_key_b64)
        .map_err(|e| PyValueError::new_err(format!("Invalid encrypted key encoding: {}", e)))?;
    
    // Ensure we have enough data for nonce (12 bytes) + ciphertext (at least 1 byte)
    if encrypted_data.len() <= 12 {
        return Err(PyValueError::new_err("Invalid encrypted key format"));
    }
    
    // Split into nonce and ciphertext
    let nonce = Nonce::from_slice(&encrypted_data[0..12]);
    let ciphertext = &encrypted_data[12..];
    
    // Use the vault key to decrypt the master key
    let cipher = Aes256Gcm::new_from_slice(cache.vault_key.as_ref().unwrap())
        .map_err(|e| PyValueError::new_err(format!("Cipher initialization error: {}", e)))?;
    
    // Decrypt the master key
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| PyValueError::new_err(format!("Decryption error: {}", e)))?;
    
    Ok(base64::encode(&plaintext))
}

/// Creates a new SecureString instance from a byte array
/// This function is used by the Python code to create SecureString objects
#[pyfunction]
fn create_secure_string(data: &[u8]) -> PyResult<SecureString> {
    // Convert the bytes to UTF-8 string for secure storage
    match std::str::from_utf8(data) {
        Ok(s) => Ok(SecureString::new(s)),
        Err(_) => {
            // If the data is not valid UTF-8, use base64 encoding
            Ok(SecureString::new(&base64::encode(data)))
        }
    }
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
    m.add_function(wrap_pyfunction!(generate_salt, m)?)?;
    m.add_function(wrap_pyfunction!(derive_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(create_secure_string, m)?)?;
    
    Ok(())
}

// Export functions with C linkage for DLL loading

/// Generate secure random bytes and copy to output buffer.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_secure_random_bytes(size: usize, out_ptr: *mut u8, out_len: *mut usize) -> bool {
    Python::with_gil(|_py| {
        match secure_random_bytes(size) {
            Ok(bytes) => {
                unsafe {
                    if bytes.len() <= size {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
                        *out_len = bytes.len();
                        true
                    } else {
                        false
                    }
                }
            },
            Err(_) => false,
        }
    })
}

/// Create a new vault with the given master password.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_create_vault(password_ptr: *const u8, password_len: usize, out_ptr: *mut u8, out_len: *mut usize) -> bool {
    let password = unsafe {
        let slice = std::slice::from_raw_parts(password_ptr, password_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    Python::with_gil(|_py| {
        match create_vault(password) {
            Ok(salt) => {
                let bytes = salt.as_bytes();
                unsafe {
                    if bytes.len() <= *out_len {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
                        *out_len = bytes.len();
                        true
                    } else {
                        false
                    }
                }
            },
            Err(_) => false,
        }
    })
}

/// Check if the vault is currently unlocked.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_is_vault_unlocked() -> bool {
    Python::with_gil(|_py| {
        match is_vault_unlocked() {
            Ok(b) => b,
            Err(_) => false,
        }
    })
}

/// Check if a vault has been initialized.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_vault_exists() -> bool {
    Python::with_gil(|_py| {
        match vault_exists() {
            Ok(b) => b,
            Err(_) => false,
        }
    })
}

/// Attempt to unlock the vault with the given password and salt.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_unlock_vault(password_ptr: *const u8, password_len: usize, salt_ptr: *const u8, salt_len: usize) -> bool {
    let password = unsafe {
        let slice = std::slice::from_raw_parts(password_ptr, password_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    let salt = unsafe {
        let slice = std::slice::from_raw_parts(salt_ptr, salt_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    Python::with_gil(|_py| {
        match unlock_vault(password, salt) {
            Ok(b) => b,
            Err(_) => false,
        }
    })
}

/// Lock the vault by clearing the active key.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_lock_vault() -> bool {
    Python::with_gil(|_py| {
        match lock_vault() {
            Ok(_) => true,
            Err(_) => false,
        }
    })
}

/// Generate a cryptographically secure random salt for key derivation.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_generate_salt(out_ptr: *mut u8, out_len: *mut usize) -> bool {
    // Generate raw random bytes first
    let mut salt_bytes = [0u8; 16]; // Same size as in generate_salt()
    
    // Fill with random data
    match OsRng.try_fill_bytes(&mut salt_bytes) {
        Ok(_) => {
            // Base64 encode the salt
            let encoded = base64::encode(&salt_bytes);
            let encoded_bytes = encoded.as_bytes();
            
            // Copy to output buffer if there's enough space
            unsafe {
                if encoded_bytes.len() <= *out_len {
                    std::ptr::copy_nonoverlapping(encoded_bytes.as_ptr(), out_ptr, encoded_bytes.len());
                    *out_len = encoded_bytes.len();
                    true
                } else {
                    false
                }
            }
        },
        Err(_) => false,
    }
}

/// Derive a master key from a password and salt.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_derive_master_key(password_ptr: *const u8, password_len: usize, salt_ptr: *const u8, salt_len: usize, out_ptr: *mut u8, out_len: *mut usize) -> bool {
    let password = unsafe {
        let slice = std::slice::from_raw_parts(password_ptr, password_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    let salt = unsafe {
        let slice = std::slice::from_raw_parts(salt_ptr, salt_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    Python::with_gil(|_py| {
        match derive_master_key(password, salt) {
            Ok(key) => {
                let bytes = key.as_bytes();
                unsafe {
                    if bytes.len() <= *out_len {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
                        *out_len = bytes.len();
                        true
                    } else {
                        false
                    }
                }
            },
            Err(_) => false,
        }
    })
}

/// Encrypt the master key using the vault key.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_encrypt_master_key(key_ptr: *const u8, key_len: usize, out_ptr: *mut u8, out_len: *mut usize) -> bool {
    let key = unsafe {
        let slice = std::slice::from_raw_parts(key_ptr, key_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    Python::with_gil(|_py| {
        match encrypt_master_key(key) {
            Ok(encrypted) => {
                let bytes = encrypted.as_bytes();
                unsafe {
                    if bytes.len() <= *out_len {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
                        *out_len = bytes.len();
                        true
                    } else {
                        false
                    }
                }
            },
            Err(_) => false,
        }
    })
}

/// Decrypt the master key using the vault key.
/// This function is exported for FFI.
#[no_mangle]
pub extern "C" fn c_decrypt_master_key(encrypted_ptr: *const u8, encrypted_len: usize, out_ptr: *mut u8, out_len: *mut usize) -> bool {
    let encrypted = unsafe {
        let slice = std::slice::from_raw_parts(encrypted_ptr, encrypted_len);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    
    Python::with_gil(|_py| {
        match decrypt_master_key(encrypted) {
            Ok(decrypted) => {
                let bytes = decrypted.as_bytes();
                unsafe {
                    if bytes.len() <= *out_len {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
                        *out_len = bytes.len();
                        true
                    } else {
                        false
                    }
                }
            },
            Err(_) => false,
        }
    })
}

/// Create a secure string object from raw data
/// This function is exported for FFI
#[no_mangle]
pub extern "C" fn c_create_secure_string(data_ptr: *const u8, data_len: usize) -> *mut SecureString {
    if data_ptr.is_null() {
        return std::ptr::null_mut();
    }
    
    let data = unsafe {
        std::slice::from_raw_parts(data_ptr, data_len)
    };
    
    Python::with_gil(|py| {
        match create_secure_string(data) {
            Ok(secure_string) => {
                let boxed = Box::new(secure_string);
                Box::into_raw(boxed)
            },
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn c_verify_signature(_data_ptr: *const u8, _data_len: usize, _signature_ptr: *const u8, _signature_len: usize) -> bool {
    // This is a placeholder function for signature verification
    // In a real implementation, this would verify a cryptographic signature
    true
}
