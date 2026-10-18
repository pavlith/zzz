package models

import "time"

// RotationCommitment is a signed assertion from a recipient device.
type RotationCommitment struct {
 RotationID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"primaryKey;size:36"`
 ManifestSHA256 string `gorm:"size:64;not null"`
 KeyCommitment string `gorm:"size:64;not null"`
 Signature []byte `gorm:"not null"`
 CreatedAt time.Time
}
