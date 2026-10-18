package api

import (
 "bytes"
 "crypto/sha256"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestUntrustedDeviceCannotReceiveVaultEnvelope(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 recipient,signer:=candidateTestKeys(t)
 manifest:=sha256.Sum256([]byte("candidate-test-manifest"))
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:fixtureVaultID,WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:fixtureVaultID,PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:fixtureDeviceID,UserID:"u",Name:"Pending",VerifiedAt:&now,SigningPublicKey:make([]byte,32),EncryptionPublicKey:recipient},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 body:=candidateTestRequest(t,fixtureDeviceID,1,candidateTestEnvelope(t,fixtureVaultID,fixtureDeviceID,fixtureRotationID,fixtureSignerID,1,recipient,signer,manifest))
 request:=func() *httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",bytes.NewBufferString(body))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Authorization","Bearer "+token)
  res:=httptest.NewRecorder();server.ServeHTTP(res,req)
  return res
 }
 if got:=request().Code;got==201{t.Fatal("untrusted device received envelope")}
 var count int64
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=0{t.Fatalf("unexpected envelopes: %d",count)}
 if err:=db.Model(&models.Device{}).Where("id = ?",fixtureDeviceID).Update("trusted_at",now).Error;err!=nil{t.Fatal(err)}
 if got:=request().Code;got!=201{t.Fatalf("trusted device envelope response: %d",got)}
}
