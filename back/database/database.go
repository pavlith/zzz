package database

import (
 "fmt"
 "os"
 "path/filepath"
 "strings"
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
// Migrate initializes the consolidated pre-v1 schema. Old development databases
// with a newer migration ledger must be reset; no silent data conversion.
func Migrate(db *gorm.DB) error {
 return applyMigrations(db)
}
