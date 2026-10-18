package models

import "time"

// ItemRevision is an immutable encrypted item version, including deletion markers.
type ItemRevision struct {
 ID uint64 `gorm:"primaryKey;autoIncrement" json:"id"`
 VaultID string `gorm:"uniqueIndex:idx_item_revision;not null" json:"vault_id"`
 ItemID string `gorm:"uniqueIndex:idx_item_revision;not null" json:"item_id"`
 Revision uint64 `gorm:"uniqueIndex:idx_item_revision;not null" json:"revision"`
 KeyEpoch uint64 `gorm:"not null" json:"key_epoch"`
 Nonce []byte `json:"nonce"`
 Ciphertext []byte `json:"ciphertext"`
 CryptoVersion uint32 `json:"crypto_version"`
 Deleted bool `gorm:"not null" json:"deleted"`
 CreatedAt time.Time `json:"created_at"`
}
