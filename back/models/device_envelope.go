package models

import "time"

// DeviceKeyEnvelope stores opaque client-produced encrypted key material.
type DeviceKeyEnvelope struct {
 ID string `gorm:"primaryKey;size:36" json:"id"`
 VaultID string `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"vault_id"`
 DeviceID string `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"device_id"`
 KeyEpoch uint64 `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"key_epoch"`
 CryptoVersion uint32 `gorm:"not null" json:"crypto_version"`
 Ciphertext []byte `gorm:"not null" json:"ciphertext"`
 CreatedAt time.Time `json:"created_at"`
}
