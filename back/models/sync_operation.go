package models

import "time"

// SyncOperation deduplicates retries for one user and one client operation ID.
type SyncOperation struct {
 ID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"uniqueIndex:idx_sync_operation;not null"`
 VaultID string `gorm:"uniqueIndex:idx_sync_operation;not null"`
 OperationID string `gorm:"uniqueIndex:idx_sync_operation;not null"`
 RequestHash string `gorm:"not null"`
 ItemID string `gorm:"not null"`
 Revision uint64 `gorm:"not null"`
 CreatedAt time.Time
}
