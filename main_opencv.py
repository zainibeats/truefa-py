# Check if vault exists
try:
    print(f"Checking vault initialization...")
    vault_initialized = secure_storage.vault.is_initialized if hasattr(secure_storage, 'vault') else False
    print(f"Vault initialization status: {vault_initialized}")
except Exception as e:
    print(f"Error checking vault initialization: {e}")
    vault_initialized = False 