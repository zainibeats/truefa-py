fn main() {
    // Tell cargo to tell rustc to link the system libraries statically
    println!("cargo:rustc-link-arg=/EXPORT:c_secure_random_bytes");
    println!("cargo:rustc-link-arg=/EXPORT:c_generate_salt");
    println!("cargo:rustc-link-arg=/EXPORT:c_derive_master_key");
    println!("cargo:rustc-link-arg=/EXPORT:c_encrypt_master_key");
    println!("cargo:rustc-link-arg=/EXPORT:c_decrypt_master_key");
    println!("cargo:rustc-link-arg=/EXPORT:c_is_vault_unlocked");
    println!("cargo:rustc-link-arg=/EXPORT:c_vault_exists");
    println!("cargo:rustc-link-arg=/EXPORT:c_create_vault");
    println!("cargo:rustc-link-arg=/EXPORT:c_unlock_vault");
    println!("cargo:rustc-link-arg=/EXPORT:c_lock_vault");
    println!("cargo:rustc-link-arg=/EXPORT:c_create_secure_string");
    println!("cargo:rustc-link-arg=/EXPORT:c_verify_signature");
    
    // Tell cargo to invalidate the built crate whenever the build script changes
    println!("cargo:rerun-if-changed=build.rs");
} 