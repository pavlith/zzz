package database

import (
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/auth"
 "gorm.io/driver/sqlite"
 "gorm.io/gorm"
)

func Open(dsn string) (*gorm.DB,error) {
 if !strings.HasPrefix(dsn,"file:") && dsn!=":memory:" {
  if err:=os.MkdirAll(filepath.Dir(dsn),0700);err!=nil{return nil,err}
 }
 db,err:=gorm.Open(sqlite.Open(dsn),&gorm.Config{TranslateError:true})
 if err!=nil{return nil,fmt.Errorf("open sqlite: %w",err)}
 db.Exec("PRAGMA foreign_keys = ON")
 db.Exec("PRAGMA busy_timeout = 5000")
 db.Exec("PRAGMA journal_mode = WAL")
 return db,nil
}
func Migrate(db *gorm.DB) error {
 // Initial schema; production migrations must be versioned before release.
 return db.AutoMigrate(
  &models.User{},&models.Workspace{},&models.WorkspaceMember{},
  &models.Group{},&models.GroupMember{},&models.Vault{},
  &models.VaultPermission{},&models.VaultKeyEnvelope{},&models.Item{},&auth.Token{},&models.Device{},
 )
}
