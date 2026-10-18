package models

import "time"

// DeviceApprovalChallenge binds an approval to a specific target and approver.
type DeviceApprovalChallenge struct {
 ID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"index;not null"`
 TargetDeviceID string `gorm:"index;not null"`
 ApproverDeviceID string `gorm:"not null"`
 Nonce []byte `gorm:"not null"`
 ExpiresAt time.Time
 UsedAt *time.Time
 CreatedAt time.Time
}
