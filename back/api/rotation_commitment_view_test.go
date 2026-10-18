package api

import (
 "bytes"
 "testing"

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationCommitmentViewStableAndDetectsFork(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 rotation:=models.VaultRotation{ID:"r",VaultID:"v",ManifestSHA256:"manifest",FromEpoch:1,ToEpoch:2,Status:"prepared"}
 if err:=db.Create(&rotation).Error;err!=nil{t.Fatal(err)}
 for _,row:=range []models.RotationCommitment{
  {RotationID:"r",DeviceID:"z",ManifestSHA256:"manifest",KeyCommitment:"same",Signature:bytes.Repeat([]byte{1},64)},
  {RotationID:"r",DeviceID:"a",ManifestSHA256:"manifest",KeyCommitment:"same",Signature:bytes.Repeat([]byte{2},64)},
 }{if err:=db.Create(&row).Error;err!=nil{t.Fatal(err)}}
 first,err:=rotationCommitmentView(db,rotation);if err!=nil{t.Fatal(err)}
 second,err:=rotationCommitmentView(db,rotation);if err!=nil{t.Fatal(err)}
 if first.ViewSHA256!=second.ViewSHA256||len(first.Entries)!=2||first.Entries[0].DeviceID!="a"{t.Fatalf("unstable view: %+v",first)}
 if err:=db.Model(&models.RotationCommitment{}).Where("rotation_id = ? AND device_id = ?","r","z").Update("key_commitment","different").Error;err!=nil{t.Fatal(err)}
 fork,err:=rotationCommitmentView(db,rotation);if err!=nil{t.Fatal(err)}
 if fork.ViewSHA256==first.ViewSHA256{t.Fatal("changed claim did not affect view hash")}
}
