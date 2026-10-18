package database

import (
 "path/filepath"
 "testing"

 "github.com/pavlith/zzz/back/models"
)

// A SQLite-native snapshot, rather than a filesystem copy of an open WAL DB,
// is required to validate an actual restore path.
func TestSQLiteVacuumBackupRestoreAcrossMigration(t *testing.T){
 dir:=t.TempDir()
 live:=filepath.Join(dir,"live.db")
 backup:=filepath.Join(dir,"backup.db")
 db,err:=Open(live);if err!=nil{t.Fatal(err)}
 if err:=baselineSchema(db);err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.User{ID:"preserved",Email:"preserved@example.test"}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("VACUUM INTO ?",backup).Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 restore,err:=Open(backup);if err!=nil{t.Fatal(err)}
 if err:=Migrate(restore);err!=nil{t.Fatalf("restored legacy DB upgrade: %v",err)}
 var u models.User
 if err:=restore.First(&u,"id = ?","preserved").Error;err!=nil||u.Email!="preserved@example.test"{t.Fatalf("lost restored record: %+v, %v",u,err)}
 if err:=checkSQLiteIntegrity(restore);err!=nil{t.Fatal(err)}
 var applied int64
 if err:=restore.Model(&schemaMigration{}).Count(&applied).Error;err!=nil||applied!=2{t.Fatalf("bad restored migration ledger: %d %v",applied,err)}
}

func TestMigrationRejectsForeignKeyCorruption(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=db.Exec("CREATE TABLE parent(id INTEGER PRIMARY KEY)").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id))").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("PRAGMA foreign_keys = OFF").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("INSERT INTO child(id,parent_id) VALUES(1,999)").Error;err!=nil{t.Fatal(err)}
 if err:=checkSQLiteIntegrity(db);err==nil{t.Fatal("orphaned FK accepted")}
 if err:=Migrate(db);err==nil{t.Fatal("migrations must reject FK corruption")}
}
