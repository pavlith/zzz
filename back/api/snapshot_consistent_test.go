package api

import (
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/service"
)

func TestConsistentSnapshotWatermark(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,row:=range []any{
  &models.User{ID:"u",Email:"u@example.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanWrite:true},
 }{if err:=db.Create(row).Error;err!=nil{t.Fatal(err)}}
 svc:=service.New(db)
 item:=&models.Item{VaultID:"v",Nonce:[]byte("nonce1"),Ciphertext:[]byte("first"),CryptoVersion:1}
 if err:=svc.PutItem("u",item,0);err!=nil{t.Fatal(err)}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 router:=New(db)
 get:=func(query string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/v/snapshot-consistent"+query,nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();router.ServeHTTP(rec,req);return rec
 }
 first:=get("")
 if first.Code!=200{t.Fatalf("initial snapshot: %d %s",first.Code,first.Body)}
 var snapshot struct{
  Revisions []models.ItemRevision `json:"revisions"`
  Watermark string `json:"watermark"`
 }
 if err:=json.Unmarshal(first.Body.Bytes(),&snapshot);err!=nil{t.Fatal(err)}
 if len(snapshot.Revisions)!=1||string(snapshot.Revisions[0].Ciphertext)!="first"{t.Fatal("incorrect initial snapshot")}
 item.Ciphertext=[]byte("second")
 if err:=svc.PutItem("u",item,1);err!=nil{t.Fatal(err)}
 later:=get("?watermark="+snapshot.Watermark)
 if later.Code!=200{t.Fatalf("pinned snapshot: %d %s",later.Code,later.Body)}
 var pinned struct{Revisions []models.ItemRevision `json:"revisions"`}
 if err:=json.Unmarshal(later.Body.Bytes(),&pinned);err!=nil{t.Fatal(err)}
 if len(pinned.Revisions)!=1||string(pinned.Revisions[0].Ciphertext)!="first"{t.Fatal("snapshot changed after watermark")}
}
