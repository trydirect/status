-- Add server selection columns for SSH key management via Vault

-- Path to SSH key stored in Vault (e.g., secret/data/users/{user_id}/ssh_keys/{server_id})
ALTER TABLE server ADD COLUMN vault_key_path VARCHAR(255) DEFAULT NULL;

-- Connection mode: 'ssh' (maintain SSH access) or 'status_panel' (disconnect SSH after install)
ALTER TABLE server ADD COLUMN connection_mode VARCHAR(20) NOT NULL DEFAULT 'ssh';

-- Key status: 'none' (no key), 'stored' (key in Vault), 'disconnected' (key removed)
ALTER TABLE server ADD COLUMN key_status VARCHAR(20) NOT NULL DEFAULT 'none';

-- Friendly display name for the server
ALTER TABLE server ADD COLUMN name VARCHAR(100) DEFAULT NULL;
