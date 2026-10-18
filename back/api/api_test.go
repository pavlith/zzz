package api

import (
 "bytes"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestAuthAndWorkspaceIsolation(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,u:=range []models.User{{ID:"alice",Email:"alice@example.test"},{ID:"bob",Email:"bob@example.test"}}{
  if err:=db.Create(&u).Error;err!=nil{t.Fatal(err)}
 }
 token,err:=auth.Issue(db,"alice",time.Hour);if err!=nil{t.Fatal(err)}
 router:=New(db)
 call:=func(method,path,body,bearer string)*httptest.ResponseRecorder{
  t.Helper()
  req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
  if bearer!=""{req.Header.Set("Authorization","Bearer "+bearer)}
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();router.ServeHTTP(rec,req);return rec
 }
 if got:=call("GET","/api/v1/me","","").Code;got!=401{t.Fatalf("anonymous got %d",got)}
 if got:=call("GET","/api/v1/me","","bad").Code;got!=401{t.Fatalf("invalid token got %d",got)}
 rec:=call("POST","/api/v1/workspaces",`{"name":"Alice","kind":"personal"}`,token)
 if rec.Code!=201{t.Fatalf("workspace got %d: %s",rec.Code,rec.Body)}
 var ws models.Workspace
 if err:=json.Unmarshal(rec.Body.Bytes(),&ws);err!=nil{t.Fatal(err)}
 var bobToken string
 bobToken,err=auth.Issue(db,"bob",time.Hour);if err!=nil{t.Fatal(err)}
 if got:=call("POST","/api/v1/workspaces/"+ws.ID+"/vaults",`{"name":"private"}`,bobToken).Code;got!=404{t.Fatalf("cross-tenant vault create got %d",got)}
 rec=call("POST","/api/v1/workspaces/"+ws.ID+"/vaults",`{"name":"private"}`,token)
 if rec.Code!=201{t.Fatalf("vault got %d: %s",rec.Code,rec.Body)}
 var vault models.Vault
 if err:=json.Unmarshal(rec.Body.Bytes(),&vault);err!=nil{t.Fatal(err)}
 if got:=call("GET","/api/v1/vaults/"+vault.ID+"/items","",token).Code;got!=404{t.Fatalf("vault without grant got %d",got)}
 rec=call("POST","/api/v1/vaults/"+vault.ID+"/permissions",`{"principal_type":"user","principal_id":"alice","read":true,"write":true}`,token)
 if rec.Code!=201{t.Fatalf("grant got %d: %s",rec.Code,rec.Body)}
 rec=call("POST","/api/v1/vaults/"+vault.ID+"/items",`{"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVydGV4dA==","crypto_version":1}`,token)
 if rec.Code!=201{t.Fatalf("item create got %d: %s",rec.Code,rec.Body)}
 var item models.Item
 if err:=json.Unmarshal(rec.Body.Bytes(),&item);err!=nil{t.Fatal(err)}
 path:="/api/v1/vaults/"+vault.ID+"/items/"+item.ID
 body:=`{"expected_revision":1,"nonce":"bm9uY2U=","ciphertext":"Y2lwaGVydGV4dA==","crypto_version":1}`
 if got:=call("PUT",path,body,token).Code;got!=200{t.Fatalf("item update got %d",got)}
 if got:=call("PUT",path,body,token).Code;got!=409{t.Fatalf("revision conflict got %d",got)}
 if got:=call("GET",path,"",bobToken).Code;got!=404{t.Fatalf("cross-tenant read got %d",got)}
}
