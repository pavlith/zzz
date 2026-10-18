package database

import (
 "errors"
 "fmt"
 "time"

 "gorm.io/gorm"
)

type schemaMigration struct {
 Version uint64 `gorm:"primaryKey"`
 AppliedAt time.Time
}

func applyMigrations(db *gorm.DB) error {
 if err:=checkSQLiteIntegrity(db);err!=nil{return err}
 // Create the tracking table before the migration transaction, because SQLite
 // AutoMigrate may rebuild tables during baseline creation.
 if err:=db.Exec("CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY, applied_at datetime NOT NULL)").Error;err!=nil{return err}
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
  {1,baselineSQL},
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
 return checkSQLiteIntegrity(db)
}
