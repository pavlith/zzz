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

func TestDirectItemWriteRequiresCurrentEpoch(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,obj:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:2},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanWrite:true},
 }{if err:=db.Create(obj).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST","/api/v1/vaults/v/items",bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if got:=call(`{"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1}`).Code;got!=400{t.Fatalf("missing epoch got %d",got)}
 if got:=call(`{"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":1}`).Code;got!=409{t.Fatalf("stale epoch got %d",got)}
 if got:=call(`{"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":2}`).Code;got!=201{t.Fatalf("current epoch got %d",got)}
}
