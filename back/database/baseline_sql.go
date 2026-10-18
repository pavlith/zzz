package database

import "gorm.io/gorm"

// baselineDDL is frozen SQLite SQL matching the original GORM v1 schema.
// New schema changes must be added as numbered migrations, never edited here.
var baselineDDL=[]string{
"CREATE TABLE IF NOT EXISTS users (id text PRIMARY KEY, email text NOT NULL, display_name text, created_at datetime)",
"CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)",
"CREATE TABLE IF NOT EXISTS workspaces (id text PRIMARY KEY, name text NOT NULL, kind text NOT NULL, created_at datetime)",
"CREATE TABLE IF NOT EXISTS workspace_members (workspace_id text, user_id text, role text NOT NULL, created_at datetime, PRIMARY KEY(workspace_id,user_id))",
"CREATE TABLE IF NOT EXISTS groups (id text PRIMARY KEY, workspace_id text NOT NULL, name text NOT NULL)",
"CREATE INDEX IF NOT EXISTS idx_groups_workspace_id ON groups(workspace_id)",
"CREATE TABLE IF NOT EXISTS group_members (group_id text, user_id text, PRIMARY KEY(group_id,user_id))",
"CREATE TABLE IF NOT EXISTS vaults (id text PRIMARY KEY, workspace_id text NOT NULL, name text NOT NULL, key_epoch integer NOT NULL DEFAULT 1, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_vaults_workspace_id ON vaults(workspace_id)",
"CREATE TABLE IF NOT EXISTS vault_permissions (id text PRIMARY KEY, vault_id text NOT NULL, principal_type text NOT NULL, principal_id text NOT NULL, can_read numeric, can_write numeric, can_manage numeric)",
"CREATE INDEX IF NOT EXISTS idx_vault_permissions_vault_id ON vault_permissions(vault_id)",
"CREATE INDEX IF NOT EXISTS idx_vault_permissions_principal_id ON vault_permissions(principal_id)",
"CREATE TABLE IF NOT EXISTS vault_key_envelopes (id text PRIMARY KEY, vault_id text NOT NULL, recipient_user_id text NOT NULL, key_epoch integer NOT NULL, ciphertext blob NOT NULL)",
"CREATE INDEX IF NOT EXISTS idx_vault_key_envelopes_vault_id ON vault_key_envelopes(vault_id)",
"CREATE INDEX IF NOT EXISTS idx_vault_key_envelopes_recipient_user_id ON vault_key_envelopes(recipient_user_id)",
"CREATE TABLE IF NOT EXISTS items (id text PRIMARY KEY, vault_id text NOT NULL, revision integer NOT NULL, nonce blob NOT NULL, ciphertext blob NOT NULL, crypto_version integer NOT NULL, created_at datetime, updated_at datetime, deleted_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_items_vault_id ON items(vault_id)",
"CREATE TABLE IF NOT EXISTS tokens (id text PRIMARY KEY, user_id text NOT NULL, device_id text, hash text NOT NULL, created_at datetime, expires_at datetime, revoked_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)",
"CREATE INDEX IF NOT EXISTS idx_tokens_device_id ON tokens(device_id)",
"CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(hash)",
"CREATE TABLE IF NOT EXISTS devices (id text PRIMARY KEY, user_id text NOT NULL, name text NOT NULL, encryption_public_key blob NOT NULL, signing_public_key blob NOT NULL, created_at datetime, verified_at datetime, trusted_at datetime, revoked_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)",
"CREATE TABLE IF NOT EXISTS device_key_envelopes (id text PRIMARY KEY, vault_id text NOT NULL, device_id text NOT NULL, key_epoch integer NOT NULL, crypto_version integer NOT NULL, ciphertext blob NOT NULL, created_at datetime)",
"CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_device_epoch ON device_key_envelopes(vault_id,device_id,key_epoch)",
"CREATE TABLE IF NOT EXISTS device_challenges (id text PRIMARY KEY, device_id text NOT NULL, nonce blob NOT NULL, expires_at datetime NOT NULL, used_at datetime, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_device_challenges_device_id ON device_challenges(device_id)",
"CREATE TABLE IF NOT EXISTS device_approval_challenges (id text PRIMARY KEY, user_id text NOT NULL, target_device_id text NOT NULL, approver_device_id text NOT NULL, nonce blob NOT NULL, expires_at datetime, used_at datetime, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_device_approval_challenges_user_id ON device_approval_challenges(user_id)",
"CREATE INDEX IF NOT EXISTS idx_device_approval_challenges_target_device_id ON device_approval_challenges(target_device_id)",
"CREATE TABLE IF NOT EXISTS device_audits (id integer PRIMARY KEY AUTOINCREMENT, user_id text NOT NULL, device_id text NOT NULL, action text NOT NULL, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_device_audits_user_id ON device_audits(user_id)",
"CREATE INDEX IF NOT EXISTS idx_device_audits_device_id ON device_audits(device_id)",
"CREATE TABLE IF NOT EXISTS device_session_challenges (id text PRIMARY KEY, device_id text NOT NULL, nonce blob NOT NULL, expires_at datetime, used_at datetime, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_device_session_challenges_device_id ON device_session_challenges(device_id)",
"CREATE TABLE IF NOT EXISTS sync_events (id integer PRIMARY KEY AUTOINCREMENT, vault_id text NOT NULL, item_id text NOT NULL, revision integer NOT NULL, operation text NOT NULL, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_sync_vault_id ON sync_events(vault_id)",
"CREATE TABLE IF NOT EXISTS sync_operations (id text PRIMARY KEY, user_id text NOT NULL, vault_id text NOT NULL, operation_id text NOT NULL, request_hash text NOT NULL, item_id text NOT NULL, revision integer NOT NULL, created_at datetime)",
"CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_operation ON sync_operations(user_id,vault_id,operation_id)",
"CREATE TABLE IF NOT EXISTS item_revisions (id integer PRIMARY KEY AUTOINCREMENT, vault_id text NOT NULL, item_id text NOT NULL, revision integer NOT NULL, key_epoch integer NOT NULL, nonce blob, ciphertext blob, crypto_version integer, deleted numeric NOT NULL, created_at datetime)",
"CREATE UNIQUE INDEX IF NOT EXISTS idx_item_revision ON item_revisions(vault_id,item_id,revision)",
"CREATE TABLE IF NOT EXISTS vault_rotations (id text PRIMARY KEY, vault_id text NOT NULL, from_epoch integer NOT NULL, to_epoch integer NOT NULL, status text NOT NULL, manifest_sha256 text, required_approvals integer NOT NULL DEFAULT 1, created_at datetime)",
"CREATE INDEX IF NOT EXISTS idx_vault_rotations_vault_id ON vault_rotations(vault_id)",
"CREATE TABLE IF NOT EXISTS rotation_recipients (rotation_id text, device_id text, user_id text NOT NULL, signing_key_sha256 text NOT NULL, encryption_key_sha256 text NOT NULL, PRIMARY KEY(rotation_id,device_id))",
"CREATE TABLE IF NOT EXISTS rotation_signatures (rotation_id text, device_id text, manifest_sha256 text NOT NULL, signature blob NOT NULL, created_at datetime, PRIMARY KEY(rotation_id,device_id))",
"CREATE TABLE IF NOT EXISTS rotation_envelope_acks (rotation_id text, device_id text, envelope_sha256 text NOT NULL, signature blob NOT NULL, created_at datetime, PRIMARY KEY(rotation_id,device_id))",
"CREATE TABLE IF NOT EXISTS rotation_history_acks (rotation_id text, device_id text, key_epoch integer, envelope_sha256 text NOT NULL, signature blob NOT NULL, created_at datetime, PRIMARY KEY(rotation_id,device_id,key_epoch))",
"CREATE TABLE IF NOT EXISTS rotation_commitments (rotation_id text, device_id text, manifest_sha256 text NOT NULL, key_commitment text NOT NULL, signature blob NOT NULL, created_at datetime, PRIMARY KEY(rotation_id,device_id))",
"CREATE TABLE IF NOT EXISTS rotation_log_entries (id integer PRIMARY KEY AUTOINCREMENT, rotation_id text NOT NULL, device_id text NOT NULL, manifest_sha256 text NOT NULL, key_commitment text NOT NULL, signature blob NOT NULL, prev_hash text NOT NULL, entry_hash text NOT NULL)",
"CREATE INDEX IF NOT EXISTS idx_rotation_log_entries_rotation_id ON rotation_log_entries(rotation_id)",
}

func baselineSQL(tx *gorm.DB)error{
 for _,statement:=range baselineDDL{
  if err:=tx.Exec(statement).Error;err!=nil{return err}
 }
 return nil
}
