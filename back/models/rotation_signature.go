package models

import "time"

// RotationSignature binds an approved manifest to the signing device.
type RotationSignature struct {
 RotationID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"primaryKey;size:36"`
 ManifestSHA256 string `gorm:"size:64;not null"`
 Signature []byte `gorm:"not null"`
 CreatedAt time.Time
}
