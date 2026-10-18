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

func TestSnapshotAccessAndEpoch(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,record:=range []any{
  &models.User{ID:"owner",Email:"owner@example.test"},
  &models.User{ID:"outsider",Email:"outsider@example.test"},
  &models.Workspace{ID:"ws",Name:"Workspace",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"ws",UserID:"owner",Role:"owner"},
  &models.Vault{ID:"v1",WorkspaceID:"ws",Name:"Vault",KeyEpoch:3},
  &models.VaultPermission{ID:"grant",VaultID:"v1",PrincipalType:"user",PrincipalID:"owner",CanRead:true},
  &models.Item{ID:"i1",VaultID:"v1",Revision:1,Nonce:[]byte("nonce"),Ciphertext:[]byte("encrypted"),CryptoVersion:1},
  &models.SyncEvent{VaultID:"v1",ItemID:"i1",Revision:1,Operation:"upsert"},
 }{
  if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}
 }
 owner,err:=auth.Issue(db,"owner",time.Hour);if err!=nil{t.Fatal(err)}
 outsider,err:=auth.Issue(db,"outsider",time.Hour);if err!=nil{t.Fatal(err)}
 router:=New(db)
 call:=func(token,path string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET",path,nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();router.ServeHTTP(rec,req);return rec
 }
 url:="/api/v1/vaults/v1/snapshot"
 if status:=call(outsider,url).Code;status!=404{t.Fatalf("outsider: %d",status)}
 if status:=call(owner,url+"?offset=-1").Code;status!=400{t.Fatalf("offset: %d",status)}
 response:=call(owner,url)
 if response.Code!=200{t.Fatalf("snapshot: %d %s",response.Code,response.Body)}
 var data struct{
  Items []models.Item `json:"items"`
  KeyEpoch uint64 `json:"key_epoch"`
  HighWatermark string `json:"high_watermark"`
 }
 if err:=json.Unmarshal(response.Body.Bytes(),&data);err!=nil{t.Fatal(err)}
 if len(data.Items)!=1||data.KeyEpoch!=3||data.HighWatermark=="0"{t.Fatalf("snapshot data: %+v",data)}
}
