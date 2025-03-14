fn main() {
    // Get the target platform to determine which export syntax to use
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    
    // List of functions to export
    let export_functions = [
        "c_secure_random_bytes",
        "c_generate_salt",
        "c_derive_master_key",
        "c_encrypt_master_key",
        "c_decrypt_master_key",
        "c_is_vault_unlocked",
        "c_vault_exists",
        "c_create_vault",
        "c_unlock_vault",
        "c_lock_vault",
        "c_create_secure_string",
        "c_verify_signature"
    ];
    
    // Use appropriate export syntax based on the target platform
    if target_os == "windows" {
        // Windows-style exports using /EXPORT:function_name
        for func in export_functions.iter() {
            println!("cargo:rustc-link-arg=/EXPORT:{}", func);
        }
    } else {
        // For Linux/Unix targets, we rely on the #[no_mangle] attribute
        // on the exported functions rather than using linker flags
        println!("cargo:rustc-cdylib-link-arg=-Wl,--export-dynamic");
    }
    
    // Tell cargo to invalidate the built crate whenever the build script changes
    println!("cargo:rerun-if-changed=build.rs");
} 