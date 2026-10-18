package database

import (
 "errors"
 "fmt"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type schemaMigration struct {
 Version uint64 `gorm:"primaryKey"`
 AppliedAt time.Time
}

// migration 1 is a frozen compatibility baseline for existing development DBs.
// Do not edit this list after release; add explicit schema migrations instead.
func baselineSchema(tx *gorm.DB) error {
 return tx.AutoMigrate(
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

func applyMigrations(db *gorm.DB) error {
 // Create the tracking table before the migration transaction, because SQLite
 // AutoMigrate may rebuild tables during baseline creation.
 if err:=db.AutoMigrate(&schemaMigration{});err!=nil{return err}
 var applied []schemaMigration
 if err:=db.Order("version").Find(&applied).Error;err!=nil{return err}
 latest:=uint64(0)
 for _,m:=range applied{
  if m.Version!=latest+1{return fmt.Errorf("non-contiguous schema migration version: %d",m.Version)}
  latest=m.Version
 }
 const current uint64=2
 if latest>current{return fmt.Errorf("database schema %d newer than server %d",latest,current)}
 migrations:=[]struct{
  version uint64
  run func(*gorm.DB)error
 }{
  {1,baselineSchema},
  {2,func(tx *gorm.DB)error{
   // Fail on duplicate prepared rotations rather than silently choosing one.
   return tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_one_prepared_rotation_per_vault ON vault_rotations(vault_id) WHERE status = 'prepared'").Error
  }},
 }
 for _,m:=range migrations{
  if m.version<=latest{continue}
  err:=db.Transaction(func(tx *gorm.DB)error{
   if err:=m.run(tx);err!=nil{return err}
   return tx.Create(&schemaMigration{Version:m.version,AppliedAt:time.Now().UTC()}).Error
  })
  if err!=nil{
   if errors.Is(err,gorm.ErrDuplicatedKey){return fmt.Errorf("migration %d: conflicting existing records: %w",m.version,err)}
   return fmt.Errorf("migration %d: %w",m.version,err)
  }
 }
 return nil
}
