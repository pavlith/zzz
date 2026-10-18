package models

import "time"

type VaultRotation struct {
 ID string `gorm:"primaryKey;size:36"`
 VaultID string `gorm:"index;not null"`
 FromEpoch uint64 `gorm:"not null"`
 ToEpoch uint64 `gorm:"not null"`
 Status string `gorm:"not null"`
 CreatedAt time.Time
}
