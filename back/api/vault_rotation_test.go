package api

import (
 "bytes"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestPrepareVaultRotation(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"u",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:bytes.Repeat([]byte{2},32)},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(method,path,body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 envelope:=`{"device_id":"d","key_epoch":2,"crypto_version":1,"ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
 if got:=call("POST","/api/v1/vaults/v/key-envelopes",envelope).Code;got!=409{t.Fatalf("unstaged envelope: %d",got)}
 if got:=call("POST","/api/v1/vaults/v/rotation/prepare","").Code;got!=201{t.Fatalf("prepare: %d",got)}
 if got:=call("POST","/api/v1/vaults/v/rotation/prepare","").Code;got!=409{t.Fatalf("duplicate prepare: %d",got)}
 if got:=call("POST","/api/v1/vaults/v/key-envelopes",envelope).Code;got!=201{t.Fatalf("staged envelope: %d",got)}
 status:=call("GET","/api/v1/vaults/v/rotation","")
 if status.Code!=200{t.Fatalf("status: %d",status.Code)}
 var info struct{Staged int64 `json:"staged_envelopes"`;CanActivate bool `json:"can_activate"`}
 if err:=json.Unmarshal(status.Body.Bytes(),&info);err!=nil{t.Fatal(err)}
 if info.Staged!=1||info.CanActivate{t.Fatalf("unsafe rotation state %+v",info)}
 var vault models.Vault
 if err:=db.First(&vault,"id = ?","v").Error;err!=nil{t.Fatal(err)}
 if vault.KeyEpoch!=1{t.Fatal("prepare changed active epoch")}
}
