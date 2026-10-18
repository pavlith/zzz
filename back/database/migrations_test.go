package database

import (
 "testing"

 "github.com/pavlith/zzz/back/models"
)

func TestVersionedMigrationsIdempotentAndUniquePrepared(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("second migration: %v",err)}
 var n int64
 if err:=db.Model(&schemaMigration{}).Count(&n).Error;err!=nil||n!=2{t.Fatalf("migration count %d: %v",n,err)}
 if err:=db.Create(&models.VaultRotation{ID:"r1",VaultID:"v",Status:"prepared",FromEpoch:1,ToEpoch:2}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.VaultRotation{ID:"r2",VaultID:"v",Status:"prepared",FromEpoch:1,ToEpoch:2}).Error;err==nil{t.Fatal("second prepared rotation accepted")}
 if err:=db.Create(&models.VaultRotation{ID:"r3",VaultID:"v",Status:"cancelled",FromEpoch:1,ToEpoch:2}).Error;err!=nil{t.Fatal(err)}
}

func TestPreV1RejectsUnknownFutureVersion(t *testing.T) {
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 if err:=db.Create(&schemaMigration{Version:3}).Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err==nil{t.Fatal("pre-v1 schema v3 must require explicit reset")}
}
