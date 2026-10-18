package models

import "time"

// DeviceChallenge is a short-lived, single-use proof-of-possession challenge.
type DeviceChallenge struct {
 ID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"index;not null"`
 Nonce []byte `gorm:"not null"`
 ExpiresAt time.Time `gorm:"not null"`
 UsedAt *time.Time
 CreatedAt time.Time
}
