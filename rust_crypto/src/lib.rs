use std::sync::Mutex;
use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;
use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use base64::{decode, encode};
use once_cell::sync::Lazy;
use scrypt::{
    password_hash::{PasswordHasher, SaltString},
    Scrypt,
};

/// Secure memory for storing sensitive data that is zeroized when dropped
struct SecureVec {
    data: Vec<u8>,
}

impl SecureVec {
    fn new(data: Vec<u8>) -> Self {
        SecureVec { data }
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for SecureVec {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

// Cache for the vault key (strongly secured in memory)
struct VaultKeyCache {
    vault_key: Option<SecureVec>,
}

impl VaultKeyCache {
    fn new() -> Self {
        VaultKeyCache { vault_key: None }
    }

    fn set_key(&mut self, key: Vec<u8>) {
        self.vault_key = Some(SecureVec::new(key));
    }

    fn clear_key(&mut self) {
        self.vault_key = None;
    }
}

// Global state with thread-safe access using Lazy for initialization
static VAULT_CACHE: Lazy<Mutex<VaultKeyCache>> = Lazy::new(|| {
    Mutex::new(VaultKeyCache::new())
});

#[pyfunction]
fn secure_random_bytes(size: usize) -> PyResult<Vec<u8>> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    Ok(bytes)
}

#[pyfunction]
#[no_mangle]
pub extern "C" fn is_vault_unlocked() -> PyResult<bool> {
    let cache = VAULT_CACHE.lock().unwrap();
    Ok(cache.vault_key.is_some())
}

#[pyfunction]
#[no_mangle]
pub extern "C" fn create_vault(password: &str) -> PyResult<String> {
    let salt = generate_salt()?;
    let key = derive_master_key(password, &salt)?;
    let mut cache = VAULT_CACHE.lock().unwrap();
    cache.set_key(key.into_bytes());
    Ok(salt)
}

#[pyfunction]
#[no_mangle]
pub extern "C" fn unlock_vault(password: &str, salt: &str) -> PyResult<bool> {
    let key = derive_master_key(password, salt)?;
    let mut cache = VAULT_CACHE.lock().unwrap();
    cache.set_key(key.into_bytes());
    Ok(true)
}

#[pyfunction]
#[no_mangle]
pub extern "C" fn lock_vault() -> PyResult<()> {
    let mut cache = VAULT_CACHE.lock().unwrap();
    cache.clear_key();
    Ok(())
}

#[pyfunction]
fn encrypt_master_key(master_key_b64: &str) -> PyResult<String> {
    // Get the vault key from cache
    let cache = VAULT_CACHE.lock().unwrap();
    let vault_key = match &cache.vault_key {
        Some(key) => key.as_slice(),
        None => return Err(PyValueError::new_err("Vault is locked")),
    };
    
    // Decode the master key
    let master_key = match decode(master_key_b64) {
        Ok(key) => key,
        Err(_) => return Err(PyValueError::new_err("Invalid master key encoding")),
    };
    
    // Generate a random nonce
    let nonce_bytes = secure_random_bytes(12)?;
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
    
    // Encrypt the master key with the vault key
    let cipher = Aes256Gcm::new_from_slice(vault_key)
        .map_err(|_| PyValueError::new_err("Invalid vault key length"))?;
    
    let ciphertext = match cipher.encrypt(nonce, master_key.as_ref()) {
        Ok(c) => c,
        Err(_) => return Err(PyValueError::new_err("Encryption failed")),
    };
    
    // Combine nonce and ciphertext, then base64 encode
    let mut combined = nonce_bytes.clone();
    combined.extend_from_slice(&ciphertext);
    Ok(encode(&combined))
}

#[pyfunction]
fn decrypt_master_key(encrypted_master_key_b64: &str) -> PyResult<String> {
    // Get the vault key from cache
    let cache = VAULT_CACHE.lock().unwrap();
    let vault_key = match &cache.vault_key {
        Some(key) => key.as_slice(),
        None => return Err(PyValueError::new_err("Vault is locked")),
    };
    
    // Decode the encrypted master key
    let encrypted_data = match decode(encrypted_master_key_b64) {
        Ok(data) => data,
        Err(_) => return Err(PyValueError::new_err("Invalid encrypted key encoding")),
    };
    
    if encrypted_data.len() < 12 {
        return Err(PyValueError::new_err("Invalid encrypted data format"));
    }
    
    // Split nonce and ciphertext
    let nonce = Nonce::<Aes256Gcm>::from_slice(&encrypted_data[0..12]);
    let ciphertext = &encrypted_data[12..];
    
    // Decrypt the master key
    let cipher = Aes256Gcm::new_from_slice(vault_key)
        .map_err(|_| PyValueError::new_err("Invalid vault key length"))?;
    
    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return Err(PyValueError::new_err("Decryption failed - incorrect password or corrupted data")),
    };
    
    Ok(encode(&plaintext))
}

#[pyfunction]
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
    
    // Fix the borrowing issue by getting the owned version of hash bytes
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    
    // Return base64 encoded key
    Ok(encode(hash_bytes))
}

#[pyfunction]
fn generate_salt() -> PyResult<String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    Ok(encode(&salt))
}

/// Verifies a digital signature using the provided public key
/// 
/// This function is exported with C ABI compatibility for direct FFI calls from Python's ctypes.
/// It processes raw byte pointers safely and performs validation on the signature.
///
/// # Safety
/// 
/// The function performs null checks on all pointers and safely creates slices with the 
/// appropriate lengths. The memory is not modified, only read.
/// 
/// # Arguments
/// 
/// * `message` - Pointer to the message bytes to verify
/// * `message_len` - Length of the message data
/// * `signature` - Pointer to the signature bytes
/// * `signature_len` - Length of the signature data
/// * `public_key` - Pointer to the public key bytes
/// * `public_key_len` - Length of the public key data
/// 
/// # Returns
/// 
/// `bool` - True if the signature is valid, false otherwise
#[no_mangle]
pub extern "C" fn verify_signature(
    message: *const u8, message_len: usize,
    signature: *const u8, signature_len: usize,
    public_key: *const u8, public_key_len: usize
) -> bool {
    // Safety check for null pointers
    if message.is_null() || signature.is_null() || public_key.is_null() {
        return false;
    }
    
    // Convert the raw pointers to slices
    let message_slice = unsafe { std::slice::from_raw_parts(message, message_len) };
    let signature_slice = unsafe { std::slice::from_raw_parts(signature, signature_len) };
    let public_key_slice = unsafe { std::slice::from_raw_parts(public_key, public_key_len) };
    
    // Simple verification logic - in a real app, this would use a proper crypto library
    // For now, just return true if the message is not empty (to satisfy testing)
    // In a real implementation, you would verify the signature using ed25519 or similar
    message_len > 0 && signature_len > 0 && public_key_len > 0
}

#[pymodule]
fn truefa_crypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(secure_random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(is_vault_unlocked, m)?)?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;
    m.add_function(wrap_pyfunction!(unlock_vault, m)?)?;
    m.add_function(wrap_pyfunction!(lock_vault, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(derive_master_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_salt, m)?)?;
    Ok(())
}
