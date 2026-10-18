package database

import (
 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// legacyBaselineSchema recreates the pre-versioned GORM development schema in
// tests only, to verify upgrades from historic databases.
func baselineSchema(db *gorm.DB) error {
 return db.AutoMigrate(
  &models.User{},&models.Workspace{},&models.WorkspaceMember{},
  &models.Group{},&models.GroupMember{},&models.Vault{},
  &models.VaultPermission{},&models.VaultKeyEnvelope{},&models.Item{},&auth.Token{},
  &models.Device{},&models.DeviceKeyEnvelope{},&models.DeviceChallenge{},
  &models.DeviceApprovalChallenge{},&models.DeviceAudit{},&models.DeviceSessionChallenge{},
  &models.SyncEvent{},&models.SyncOperation{},&models.ItemRevision{},&models.VaultRotation{},
  &models.RotationRecipient{},&models.RotationSignature{},&models.RotationEnvelopeAck{},
  &models.RotationHistoryAck{},&models.RotationCommitment{},&models.RotationLogEntry{},
 )
}
