package models

import "time"

type DeviceSessionChallenge struct {
 ID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"index;not null"`
 Nonce []byte `gorm:"not null"`
 ExpiresAt time.Time
 UsedAt *time.Time
 CreatedAt time.Time
}
