package models

// RotationLogEntry is an append-only commitment history entry per rotation.
// Production deployments require externally witnessed checkpoints.
type RotationLogEntry struct {
 ID uint64 `gorm:"primaryKey;autoIncrement" json:"sequence"`
 RotationID string `gorm:"index;not null" json:"rotation_id"`
 DeviceID string `gorm:"not null" json:"device_id"`
 ManifestSHA256 string `gorm:"not null" json:"manifest_sha256"`
 KeyCommitment string `gorm:"not null" json:"key_commitment"`
 Signature []byte `gorm:"not null" json:"signature"`
 PrevHash string `gorm:"not null" json:"prev_hash"`
 EntryHash string `gorm:"not null" json:"entry_hash"`
}
