package models

import "time"

// DeviceAudit records non-secret device lifecycle metadata.
type DeviceAudit struct {
 ID uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
 UserID string `gorm:"index;not null" json:"user_id"`
 DeviceID string `gorm:"index;not null" json:"device_id"`
 Action string `gorm:"not null" json:"action"`
 CreatedAt time.Time `json:"created_at"`
}
