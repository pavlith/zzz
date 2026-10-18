package models

import "time"

// SyncEvent describes a committed item revision. Payloads remain in encrypted Items.
type SyncEvent struct {
 ID uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
 VaultID string `gorm:"index:idx_sync_vault_id;not null" json:"vault_id"`
 ItemID string `gorm:"not null" json:"item_id"`
 Revision uint64 `gorm:"not null" json:"revision"`
 Operation string `gorm:"not null" json:"operation"`
 CreatedAt time.Time `json:"created_at"`
}
