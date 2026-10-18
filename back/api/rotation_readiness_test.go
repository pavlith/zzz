package api

import (
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationReadiness(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,v:=range []any{
  &models.User{ID:"owner",Email:"owner@invalid.test"},
  &models.User{ID:"other",Email:"other@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"owner",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:2},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"owner",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"owner",Name:"Device",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:make([]byte,32),EncryptionPublicKey:make([]byte,32)},
  &models.Device{ID:"d2",UserID:"other",Name:"Other",VerifiedAt:&now,SigningPublicKey:make([]byte,32),EncryptionPublicKey:make([]byte,32)},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 owner,_:=auth.Issue(db,"owner",time.Hour)
 other,_:=auth.Issue(db,"other",time.Hour)
 server:=New(db)
 call:=func(token string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/v/rotation-readiness",nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if got:=call(other).Code;got!=404{t.Fatalf("unauthorized: %d",got)}
 response:=call(owner)
 if response.Code!=200{t.Fatalf("readiness: %d %s",response.Code,response.Body)}
 var result struct{
  Current uint64 `json:"current_key_epoch"`
  Proposed uint64 `json:"proposed_key_epoch"`
  Devices []struct{DeviceID string `json:"device_id"`} `json:"eligible_devices"`
  CanActivate bool `json:"can_activate"`
 }
 if err:=json.Unmarshal(response.Body.Bytes(),&result);err!=nil{t.Fatal(err)}
 if result.Current!=2||result.Proposed!=3||len(result.Devices)!=1||result.Devices[0].DeviceID!="d"||result.CanActivate{t.Fatalf("unexpected result: %+v",result)}
 var vault models.Vault
 if err:=db.First(&vault,"id = ?","v").Error;err!=nil{t.Fatal(err)}
 if vault.KeyEpoch!=2{t.Fatal("readiness changed key epoch")}
}
