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

func TestEnvelopeColumnMigrationPreservesExistingBytes(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=db.Exec("CREATE TABLE device_key_envelopes (id text PRIMARY KEY, vault_id text, device_id text, key_epoch integer, crypto_version integer, ciphertext blob, created_at datetime)").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("INSERT INTO device_key_envelopes(id,vault_id,device_id,key_epoch,crypto_version,ciphertext) VALUES(?,?,?,?,?,?)","old","vault","device",1,1,[]byte("signed-envelope")).Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("ALTER TABLE device_key_envelopes RENAME COLUMN ciphertext TO envelope").Error;err!=nil{t.Fatal(err)}
 var record models.DeviceKeyEnvelope
 if err:=db.First(&record,"id = ?","old").Error;err!=nil{t.Fatal(err)}
 if string(record.Envelope)!="signed-envelope"{t.Fatalf("envelope changed: %q",record.Envelope)}
 if err:=db.Model(&record).Update("envelope",[]byte("updated-envelope")).Error;err!=nil{t.Fatal(err)}
 if err:=db.First(&record,"id = ?","old").Error;err!=nil{t.Fatal(err)}
 if string(record.Envelope)!="updated-envelope"{t.Fatalf("envelope update failed: %q",record.Envelope)}
}

func TestFreshMigrationUsesEnvelopeColumn(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 if !db.Migrator().HasColumn(&models.DeviceKeyEnvelope{},"envelope"){t.Fatal("envelope column missing")}
 if db.Migrator().HasColumn(&models.DeviceKeyEnvelope{},"ciphertext"){t.Fatal("legacy ciphertext column remains")}
}
