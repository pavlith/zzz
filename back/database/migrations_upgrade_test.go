package database

import (
 "path/filepath"
 "testing"

 "github.com/pavlith/zzz/back/models"
)

func TestMigrateExistingDatabasePreservesData(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"legacy.sqlite")
 db,err:=Open(path);if err!=nil{t.Fatal(err)}
 // A DB created by the previous releases had GORM tables but no migration ledger.
 if err:=baselineSchema(db);err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.User{ID:"old-user",Email:"legacy@example.test"}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.VaultRotation{ID:"cancelled-old",VaultID:"old-vault",FromEpoch:1,ToEpoch:2,Status:"cancelled"}).Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("legacy upgrade: %v",err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("repeat upgrade: %v",err)}
 var user models.User
 if err:=db.First(&user,"id = ?","old-user").Error;err!=nil||user.Email!="legacy@example.test"{t.Fatalf("legacy user lost: %+v %v",user,err)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"id = ?","cancelled-old").Error;err!=nil||rotation.Status!="cancelled"{t.Fatalf("legacy rotation lost: %+v %v",rotation,err)}
 var versions []schemaMigration
 if err:=db.Order("version").Find(&versions).Error;err!=nil{t.Fatal(err)}
 if len(versions)!=2||versions[0].Version!=1||versions[1].Version!=2{t.Fatalf("unexpected migration ledger: %+v",versions)}
}

func TestMigrationFailureDoesNotMarkApplied(t *testing.T) {
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=baselineSchema(db);err!=nil{t.Fatal(err)}
 for _,id:=range []string{"a","b"} {
  if err:=db.Create(&models.VaultRotation{ID:id,VaultID:"v",FromEpoch:1,ToEpoch:2,Status:"prepared"}).Error;err!=nil{t.Fatal(err)}
 }
 if err:=Migrate(db);err==nil{t.Fatal("migration must reject duplicate prepared rotations")}
 var versions []schemaMigration
 if err:=db.Order("version").Find(&versions).Error;err!=nil{t.Fatal(err)}
 if len(versions)!=1||versions[0].Version!=1{t.Fatalf("failed migration recorded: %+v",versions)}
 var count int64
 if err:=db.Model(&models.VaultRotation{}).Where("status = ?","prepared").Count(&count).Error;err!=nil||count!=2{t.Fatalf("existing rows mutated: %d %v",count,err)}
 if err:=db.Model(&models.VaultRotation{}).Where("id = ?","b").Update("status","cancelled").Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("migration retry after repair: %v",err)}
}
