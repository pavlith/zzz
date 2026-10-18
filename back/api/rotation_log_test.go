package api

import (
 "bytes"
 "errors"
 "testing"
 "gorm.io/gorm"

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationTransparencyChain(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 a:=models.RotationCommitment{RotationID:"r",DeviceID:"a",ManifestSHA256:"manifest",KeyCommitment:"first",Signature:bytes.Repeat([]byte{1},64)}
 b:=models.RotationCommitment{RotationID:"r",DeviceID:"b",ManifestSHA256:"manifest",KeyCommitment:"second",Signature:bytes.Repeat([]byte{2},64)}
 if err:=db.Transaction(func(tx *gorm.DB)error{
  if err:=appendRotationCommitment(tx,a);err!=nil{return err}
  return appendRotationCommitment(tx,b)
 });err!=nil{t.Fatal(err)}
 entries,err:=rotationLogRead(db,"r")
 if err!=nil{t.Fatal(err)}
 if len(entries)!=2||entries[0].PrevHash!=""||entries[1].PrevHash!=entries[0].EntryHash{t.Fatalf("invalid chain: %+v",entries)}
 if err:=db.Model(&models.RotationLogEntry{}).Where("id = ?",entries[0].ID).Update("key_commitment","tampered").Error;err!=nil{t.Fatal(err)}
 if _,err:=rotationLogRead(db,"r");!errors.Is(err,errRotationLogCorrupt){t.Fatalf("tampered history accepted: %v",err)}
}
