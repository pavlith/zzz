package models

import "time"

// Workspace is the tenancy boundary. Vault is the encryption and access boundary.
type User struct {
 ID string `gorm:"primaryKey;size:36"`
 Email string `gorm:"uniqueIndex;not null"`
 DisplayName string
 CreatedAt time.Time
}
type Workspace struct {
 ID string `gorm:"primaryKey;size:36"`
 Name string `gorm:"not null"`
 Kind string `gorm:"not null"`
 CreatedAt time.Time
}
type WorkspaceMember struct {
 WorkspaceID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"primaryKey;size:36"`
 Role string `gorm:"not null"` // owner/admin/member
 CreatedAt time.Time
}
type Group struct {
 ID string `gorm:"primaryKey;size:36"`
 WorkspaceID string `gorm:"index;not null"`
 Name string `gorm:"not null"`
}
type GroupMember struct {
 GroupID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"primaryKey;size:36"`
}
type Vault struct {
 ID string `gorm:"primaryKey;size:36"`
 WorkspaceID string `gorm:"index;not null"`
 Name string `gorm:"not null"` // treat as server-visible metadata; encrypt client-side if sensitive
 KeyEpoch uint64 `gorm:"not null;default:1"`
 CreatedAt time.Time
}
type VaultPermission struct {
 ID string `gorm:"primaryKey;size:36"`
 VaultID string `gorm:"index;not null"`
 PrincipalType string `gorm:"not null"` // user or group
 PrincipalID string `gorm:"index;not null"`
 CanRead bool
 CanWrite bool
 CanManage bool
}
type VaultKeyEnvelope struct {
 ID string `gorm:"primaryKey;size:36"`
 VaultID string `gorm:"index;not null"`
 RecipientUserID string `gorm:"index;not null"`
 KeyEpoch uint64 `gorm:"not null"`
 Ciphertext []byte `gorm:"not null"`
}
type Item struct {
 ID string `gorm:"primaryKey;size:36"`
 VaultID string `gorm:"index;not null"`
 Revision uint64 `gorm:"not null"`
 Nonce []byte `gorm:"not null"`
 Ciphertext []byte `gorm:"not null"`
 CryptoVersion uint32 `gorm:"not null"`
 CreatedAt time.Time
 UpdatedAt time.Time
 DeletedAt *time.Time
}
