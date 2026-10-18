package models

import "time"

// RotationEnvelopeAck records a signed client assertion, not server decryption proof.
type RotationEnvelopeAck struct {
 RotationID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"primaryKey;size:36"`
 EnvelopeSHA256 string `gorm:"size:64;not null"`
 Signature []byte `gorm:"not null"`
 CreatedAt time.Time
}
