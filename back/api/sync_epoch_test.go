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

func TestSyncPushRejectsStaleEpoch(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,v:=range []any{
  &models.User{ID:"a",Email:"a@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"a",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:2},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"a",CanRead:true,CanWrite:true},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"a",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 post:=func(body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST","/api/v1/vaults/v/sync/push",bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  out:=httptest.NewRecorder();server.ServeHTTP(out,req);return out
 }
 stale:=`{"operation_id":"c3db7fb9-7578-4b11-a2bb-3d009a9d9770","type":"upsert","nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":1}`
 if got:=post(stale).Code;got!=409{t.Fatalf("stale epoch: %d",got)}
 current:=`{"operation_id":"c3db7fb9-7578-4b11-a2bb-3d009a9d9770","type":"upsert","nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":2}`
 if got:=post(current).Code;got!=200{t.Fatalf("valid epoch: %d",got)}
 if err:=db.Model(&models.Vault{}).Where("id = ?","v").Update("key_epoch",3).Error;err!=nil{t.Fatal(err)}
 if got:=post(current).Code;got!=200{t.Fatalf("previously committed replay: %d",got)}
 different:=`{"operation_id":"c3db7fb9-7578-4b11-a2bb-3d009a9d9771","type":"upsert","nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":2}`
 if got:=post(different).Code;got!=409{t.Fatalf("new write with old epoch: %d",got)}
 var count int64
 if err:=db.Model(&models.SyncEvent{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("events after replays: %d",count)}
}
