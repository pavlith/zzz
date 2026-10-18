package api

import (
 "testing"
 "time"

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestHistoricalEnvelopeCoverage(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:3},
  &models.VaultRotation{ID:"rotation",VaultID:"v",FromEpoch:3,ToEpoch:4,Status:"prepared"},
  &models.RotationRecipient{RotationID:"rotation",DeviceID:"d",UserID:"u"},
  &models.ItemRevision{VaultID:"v",ItemID:"a",Revision:1,KeyEpoch:1,CreatedAt:time.Now()},
  &models.ItemRevision{VaultID:"v",ItemID:"a",Revision:2,KeyEpoch:2,CreatedAt:time.Now()},
  &models.DeviceKeyEnvelope{ID:"e1",VaultID:"v",DeviceID:"d",KeyEpoch:1,CryptoVersion:1,Envelope:[]byte("ciphertext")},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 rotation:=models.VaultRotation{ID:"rotation",VaultID:"v",FromEpoch:3,ToEpoch:4}
 members:=[]models.RotationRecipient{{RotationID:"rotation",DeviceID:"d",UserID:"u"}}
 coverage,err:=historicalEnvelopeCoverage(db,rotation,members)
 if err!=nil{t.Fatal(err)}
 if coverage.Complete||len(coverage.RequiredEpochs)!=2||len(coverage.Missing)!=1||coverage.Missing[0].KeyEpoch!=2{t.Fatalf("incorrect coverage: %+v",coverage)}
 if err:=db.Create(&models.DeviceKeyEnvelope{ID:"e2",VaultID:"v",DeviceID:"d",KeyEpoch:2,CryptoVersion:1,Envelope:[]byte("ciphertext")}).Error;err!=nil{t.Fatal(err)}
 coverage,err=historicalEnvelopeCoverage(db,rotation,members)
 if err!=nil{t.Fatal(err)}
 if !coverage.Complete||len(coverage.Missing)!=0{t.Fatalf("incomplete coverage after rewrap: %+v",coverage)}
}
