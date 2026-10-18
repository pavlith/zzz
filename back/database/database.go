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
// Migrate applies tracked schema versions. Version 1 creates the legacy baseline
// schema, version 2 enforces one pending rotation per vault.
func Migrate(db *gorm.DB) error {
 return applyMigrations(db)
}
