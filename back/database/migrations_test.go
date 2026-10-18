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

func TestEnvelopeMigrationIsIdempotentWithStoredRecord(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 record:=models.DeviceKeyEnvelope{ID:"record",VaultID:"vault",DeviceID:"device",KeyEpoch:1,CryptoVersion:1,Envelope:[]byte("signed-envelope")}
 if err:=db.Create(&record).Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("repeat migration: %v",err)}
 var got models.DeviceKeyEnvelope
 if err:=db.First(&got,"id = ?","record").Error;err!=nil{t.Fatal(err)}
 if string(got.Envelope)!="signed-envelope"{t.Fatalf("envelope changed on repeat migration: %q",got.Envelope)}
}

func TestUpgradeFromVersionOnePreservesEnvelope(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=db.Exec("CREATE TABLE schema_migrations (version integer PRIMARY KEY, applied_at datetime NOT NULL)").Error;err!=nil{t.Fatal(err)}
 if err:=baselineSQL(db);err!=nil{t.Fatal(err)}
 if err:=db.Exec("INSERT INTO schema_migrations(version,applied_at) VALUES(1,CURRENT_TIMESTAMP)").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("INSERT INTO device_key_envelopes(id,vault_id,device_id,key_epoch,crypto_version,ciphertext) VALUES(?,?,?,?,?,?)","old","vault","device",1,1,[]byte("signed-envelope")).Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatal(err)}
 var got models.DeviceKeyEnvelope
 if err:=db.First(&got,"id = ?","old").Error;err!=nil{t.Fatal(err)}
 if string(got.Envelope)!="signed-envelope"{t.Fatalf("migration lost envelope: %q",got.Envelope)}
 if err:=Migrate(db);err!=nil{t.Fatalf("second upgrade: %v",err)}
 var count int64
 if err:=db.Model(&schemaMigration{}).Count(&count).Error;err!=nil||count!=2{t.Fatalf("unexpected migration ledger: %d %v",count,err)}
}

func TestFailedEnvelopeUpgradeDoesNotAdvanceMigrationLedger(t *testing.T){
 db,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=db.Exec("CREATE TABLE schema_migrations (version integer PRIMARY KEY, applied_at datetime NOT NULL)").Error;err!=nil{t.Fatal(err)}
 if err:=db.Exec("INSERT INTO schema_migrations(version,applied_at) VALUES(1,CURRENT_TIMESTAMP)").Error;err!=nil{t.Fatal(err)}
 // A damaged version-one database lacks the table required by migration two.
 if err:=Migrate(db);err==nil{t.Fatal("migration unexpectedly succeeded without device envelope table")}
 var count int64
 if err:=db.Model(&schemaMigration{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("failed migration advanced ledger to %d entries",count)}
 // Restoring the missing legacy table must allow the same migration to retry.
 if err:=db.Exec("CREATE TABLE device_key_envelopes (id text PRIMARY KEY, vault_id text, device_id text, key_epoch integer, crypto_version integer, ciphertext blob, created_at datetime)").Error;err!=nil{t.Fatal(err)}
 if err:=Migrate(db);err!=nil{t.Fatalf("retry migration: %v",err)}
 if !db.Migrator().HasColumn(&models.DeviceKeyEnvelope{},"envelope"){t.Fatal("retry did not rename envelope column")}
}
