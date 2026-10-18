package api

import (
 "bytes"
 "encoding/json"
 "fmt"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestPushIdempotencyAndDelete(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,value:=range []interface{}{
  &models.User{ID:"u",Email:"u@example.test"},
  &models.Workspace{ID:"w",Name:"Workspace",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanWrite:true},
 } {if err:=db.Create(value).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 router:=New(db)
 push:=func(body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST","/api/v1/vaults/v/sync/push",bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();router.ServeHTTP(rec,req);return rec
 }
 body:=`{"operation_id":"4dd88e79-f4be-4bc7-8bc1-41ad4694d65d","type":"upsert","nonce":"bm9uY2U=","ciphertext":"Y2lwaGVy","crypto_version":1,"key_epoch":1}`
 res:=push(body)
 if res.Code!=200{t.Fatalf("create: %d %s",res.Code,res.Body)}
 var output struct {ItemID string `json:"item_id"`;Revision uint64 `json:"revision"`;Replayed bool `json:"replayed"`}
 if err:=json.Unmarshal(res.Body.Bytes(),&output);err!=nil{t.Fatal(err)}
 if output.ItemID==""||output.Revision!=1{t.Fatalf("create: %+v",output)}
 res=push(body)
 if res.Code!=200{t.Fatalf("replay: %d %s",res.Code,res.Body)}
 var again struct{Replayed bool `json:"replayed"`}
 if err:=json.Unmarshal(res.Body.Bytes(),&again);err!=nil{t.Fatal(err)}
 if !again.Replayed{t.Fatal("expected replay")}
 if got:=push(`{"operation_id":"4dd88e79-f4be-4bc7-8bc1-41ad4694d65d","type":"upsert","nonce":"bm9uY2U=","ciphertext":"ZGlmZmVyZW50","crypto_version":1,"key_epoch":1}`).Code;got!=409{t.Fatalf("operation reused: %d",got)}
 del:=fmt.Sprintf(`{"operation_id":"8a98b003-6b89-4c67-93a6-7652b0c43db1","type":"delete","item_id":"%s","expected_revision":1,"key_epoch":1}`,output.ItemID)
 if got:=push(del).Code;got!=200{t.Fatalf("delete: %d",got)}
 if got:=push(del).Code;got!=200{t.Fatalf("delete replay: %d",got)}
 var events []models.SyncEvent
 if err:=db.Order("id").Find(&events).Error;err!=nil{t.Fatal(err)}
 if len(events)!=2||events[0].Operation!="upsert"||events[1].Operation!="delete"{t.Fatalf("events: %+v",events)}
 var item models.Item
 if err:=db.First(&item,"id = ?",output.ItemID).Error;err!=nil{t.Fatal(err)}
 if item.DeletedAt==nil||item.Revision!=2{t.Fatalf("tombstone: %+v",item)}
}
