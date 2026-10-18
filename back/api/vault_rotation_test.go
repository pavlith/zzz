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
 recipient,signer:=candidateTestKeys(t)
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:fixtureVaultID,WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:fixtureVaultID,PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:fixtureDeviceID,UserID:"u",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:recipient},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(method,path,body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 envelope:=candidateTestRequest(t,fixtureDeviceID,2,candidateTestEnvelope(t,fixtureVaultID,fixtureDeviceID,fixtureRotationID,fixtureSignerID,2,recipient,signer,candidateTestManifest()))
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",envelope).Code;got!=409{t.Fatalf("unstaged envelope: %d",got)}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/prepare","").Code;got!=201{t.Fatalf("prepare: %d",got)}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/prepare","").Code;got!=409{t.Fatalf("duplicate prepare: %d",got)}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",envelope).Code;got!=201{t.Fatalf("staged envelope: %d",got)}
 status:=call("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation","")
 if status.Code!=200{t.Fatalf("status: %d",status.Code)}
 var info struct{Staged int64 `json:"staged_envelopes"`;CanActivate bool `json:"can_activate"`}
 if err:=json.Unmarshal(status.Body.Bytes(),&info);err!=nil{t.Fatal(err)}
 if info.Staged!=1||info.CanActivate{t.Fatalf("unsafe rotation state %+v",info)}
 var vault models.Vault
 if err:=db.First(&vault,"id = ?",fixtureVaultID).Error;err!=nil{t.Fatal(err)}
 if vault.KeyEpoch!=1{t.Fatal("prepare changed active epoch")}
}
