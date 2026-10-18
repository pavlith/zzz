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

func TestEncryptedRevisionHistory(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 records:=[]any{
  &models.User{ID:"alice",Email:"alice@invalid.test"},
  &models.User{ID:"bob",Email:"bob@invalid.test"},
  &models.Workspace{ID:"w",Name:"Private",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"alice",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Private",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"alice",CanRead:true,CanWrite:true},
 }
 for _,record:=range records {if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 svc:=service.New(db)
 item:=&models.Item{VaultID:"v",Nonce:[]byte("n1"),Ciphertext:[]byte("encrypted1"),CryptoVersion:1}
 if err:=svc.PutItem("alice",item,0);err!=nil{t.Fatal(err)}
 item.Nonce=[]byte("n2");item.Ciphertext=[]byte("encrypted2")
 if err:=svc.PutItem("alice",item,1);err!=nil{t.Fatal(err)}
 if _,err:=svc.DeleteItem("alice","v",item.ID,2);err!=nil{t.Fatal(err)}
 alice,_:=auth.Issue(db,"alice",time.Hour)
 bob,_:=auth.Issue(db,"bob",time.Hour)
 router:=New(db)
 request:=func(token string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/v/items/"+item.ID+"/revisions",nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();router.ServeHTTP(rec,req);return rec
 }
 if got:=request(bob).Code;got!=404{t.Fatalf("outsider status %d",got)}
 res:=request(alice)
 if res.Code!=200{t.Fatalf("owner status %d: %s",res.Code,res.Body)}
 var response struct{Revisions []models.ItemRevision `json:"revisions"`}
 if err:=json.Unmarshal(res.Body.Bytes(),&response);err!=nil{t.Fatal(err)}
 rows:=response.Revisions
 if len(rows)!=3||rows[0].Revision!=1||rows[1].Revision!=2||rows[2].Revision!=3||!rows[2].Deleted{
  t.Fatalf("incorrect revisions %+v",rows)
 }
 if string(rows[0].Ciphertext)!="encrypted1"||string(rows[1].Ciphertext)!="encrypted2"{t.Fatal("historical payload mismatch")}
}
