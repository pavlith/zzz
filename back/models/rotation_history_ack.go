package models

import "time"

// RotationHistoryAck stores a signed device claim for a specific historic envelope.
type RotationHistoryAck struct {
 RotationID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"primaryKey;size:36"`
 KeyEpoch uint64 `gorm:"primaryKey"`
 EnvelopeSHA256 string `gorm:"size:64;not null"`
 Signature []byte `gorm:"not null"`
 CreatedAt time.Time
}
