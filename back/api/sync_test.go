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
 "github.com/pavlith/zzz/back/service"
)

func TestVaultSyncCursor(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err=db.Migrator().AutoMigrate(&models.SyncEvent{});err!=nil{t.Fatal(err)}
 if err=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,u:=range []models.User{{ID:"a",Email:"a@example.test"},{ID:"b",Email:"b@example.test"}}{
  if err=db.Create(&u).Error;err!=nil{t.Fatal(err)}
 }
 db.Create(&models.Workspace{ID:"w",Name:"Work",Kind:"personal"})
 db.Create(&models.WorkspaceMember{WorkspaceID:"w",UserID:"a",Role:"owner"})
 db.Create(&models.Vault{ID:"v",WorkspaceID:"w",Name:"Secrets",KeyEpoch:1})
 db.Create(&models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"a",CanRead:true,CanWrite:true})
 svc:=service.New(db)
 item:=&models.Item{VaultID:"v",Nonce:[]byte("nonce"),Ciphertext:[]byte("ciphertext"),CryptoVersion:1}
 if err=svc.PutItem("a",item,0);err!=nil{t.Fatal(err)}
 item.Nonce=[]byte("new-nonce");item.Ciphertext=[]byte("new-ciphertext")
 if err=svc.PutItem("a",item,1);err!=nil{t.Fatal(err)}
 alice,_:=auth.Issue(db,"a",time.Hour)
 bob,_:=auth.Issue(db,"b",time.Hour)
 h:=New(db)
 call:=func(token,cursor string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/v/sync?cursor="+cursor,bytes.NewReader(nil))
  req.Header.Set("Authorization","Bearer "+token)
  w:=httptest.NewRecorder();h.ServeHTTP(w,req);return w
 }
 if got:=call(bob,"0").Code;got!=404{t.Fatalf("cross-tenant status: %d",got)}
 res:=call(alice,"0")
 if res.Code!=200{t.Fatalf("sync status: %d %s",res.Code,res.Body)}
 var page struct{Events []models.SyncEvent `json:"events"`;NextCursor string `json:"next_cursor"`}
 if err=json.Unmarshal(res.Body.Bytes(),&page);err!=nil{t.Fatal(err)}
 if len(page.Events)!=2{t.Fatalf("events: %d",len(page.Events))}
 if page.Events[0].Revision!=1||page.Events[1].Revision!=2{t.Fatal("incorrect revisions")}
 second:=call(alice,page.NextCursor)
 if second.Code!=200{t.Fatalf("second status: %d",second.Code)}
 var empty struct{Events []models.SyncEvent `json:"events"`}
 if err=json.Unmarshal(second.Body.Bytes(),&empty);err!=nil{t.Fatal(err)}
 if len(empty.Events)!=0{t.Fatalf("duplicate events: %d",len(empty.Events))}
}
