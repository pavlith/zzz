package models

type RotationRecipient struct {
 RotationID string `gorm:"primaryKey;size:36"`
 DeviceID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"not null"`
 SigningKeySHA256 string `gorm:"size:64;not null"`
 EncryptionKeySHA256 string `gorm:"size:64;not null"`
}
