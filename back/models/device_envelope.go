package models

import "time"

// DeviceKeyEnvelope stores canonical, structurally validated candidate-v1 JSON.
// Envelope holds the complete signed candidate-v1 JSON, not raw ciphertext. Signer trust is
// verified by clients, not by this storage model.
type DeviceKeyEnvelope struct {
 ID string `gorm:"primaryKey;size:36" json:"id"`
 VaultID string `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"vault_id"`
 DeviceID string `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"device_id"`
 KeyEpoch uint64 `gorm:"uniqueIndex:idx_vault_device_epoch;not null" json:"key_epoch"`
 // CryptoVersion is a pre-v1 storage discriminator fixed to 1 by write APIs.
 // It must not be interpreted as proof of cryptographic validation.
 CryptoVersion uint32 `gorm:"not null" json:"crypto_version"`
 Envelope []byte `gorm:"column:envelope;not null" json:"-"`
 CreatedAt time.Time `json:"created_at"`
}
