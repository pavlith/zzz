package models

import "time"

type VaultRotation struct {
 ID string `gorm:"primaryKey;size:36"`
 VaultID string `gorm:"index;not null"`
 FromEpoch uint64 `gorm:"not null"`
 ToEpoch uint64 `gorm:"not null"`
 Status string `gorm:"not null"`
 ManifestSHA256 string `gorm:"size:64" json:"manifest_sha256"`
 RequiredApprovals uint32 `gorm:"not null;default:1" json:"required_approvals"`
 CreatedAt time.Time
}
