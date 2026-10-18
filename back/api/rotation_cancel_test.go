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

func TestRotationReadinessAndCancellation(t *testing.T) {
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
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/prepare","").Code;got!=201{t.Fatalf("prepare: %d",got)}
 status:=call("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation","")
 if status.Code!=200{t.Fatalf("status: %d",status.Code)}
 var state struct{Missing []string `json:"missing_device_ids"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(status.Body.Bytes(),&state);err!=nil{t.Fatal(err)}
 if len(state.Missing)!=1||state.Missing[0]!=fixtureDeviceID||state.Complete{t.Fatalf("unexpected readiness %+v",state)}
 envelope:=candidateTestRequest(t,fixtureDeviceID,2,candidateTestEnvelope(t,fixtureVaultID,fixtureDeviceID,fixtureRotationID,fixtureSignerID,2,recipient,signer,candidateTestManifest()))
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",envelope).Code;got!=201{t.Fatalf("stage: %d",got)}
 preflight:=call("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation/preflight","")
 if preflight.Code!=200{t.Fatalf("preflight: %d %s",preflight.Code,preflight.Body)}
 var check struct{CanActivate bool `json:"can_activate"`;Blockers []string `json:"blockers"`;EnvelopesComplete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(preflight.Body.Bytes(),&check);err!=nil{t.Fatal(err)}
 if check.CanActivate||!check.EnvelopesComplete||len(check.Blockers)==0{t.Fatalf("unsafe preflight: %+v",check)}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/activate","").Code;got!=409{t.Fatalf("unsafe activation accepted: %d",got)}
 var beforeCancel models.Vault
 if err:=db.First(&beforeCancel,"id = ?",fixtureVaultID).Error;err!=nil{t.Fatal(err)}
 if beforeCancel.KeyEpoch!=1{t.Fatal("activation guard changed key epoch")}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/cancel","").Code;got!=200{t.Fatalf("cancel: %d",got)}
 if got:=call("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/cancel","").Code;got!=404{t.Fatalf("duplicate cancel: %d",got)}
 var vault models.Vault
 if err:=db.First(&vault,"id = ?",fixtureVaultID).Error;err!=nil{t.Fatal(err)}
 if vault.KeyEpoch!=1{t.Fatal("active key epoch changed")}
 var staged int64
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND key_epoch = ?", fixtureVaultID,2).Count(&staged).Error;err!=nil{t.Fatal(err)}
 if staged!=0{t.Fatalf("pending envelopes left: %d",staged)}
}
