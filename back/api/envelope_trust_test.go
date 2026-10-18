package api

import (
 "bytes"
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
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"u",Name:"Pending",VerifiedAt:&now,SigningPublicKey:make([]byte,32),EncryptionPublicKey:make([]byte,32)},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 body:=`{"device_id":"d","key_epoch":1,"crypto_version":1,"ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
 request:=func() *httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST","/api/v1/vaults/v/key-envelopes",bytes.NewBufferString(body))
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("Authorization","Bearer "+token)
  res:=httptest.NewRecorder();server.ServeHTTP(res,req)
  return res
 }
 if got:=request().Code;got==201{t.Fatal("untrusted device received envelope")}
 var count int64
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=0{t.Fatalf("unexpected envelopes: %d",count)}
 if err:=db.Model(&models.Device{}).Where("id = ?","d").Update("trusted_at",now).Error;err!=nil{t.Fatal(err)}
 if got:=request().Code;got!=201{t.Fatalf("trusted device envelope response: %d",got)}
}
