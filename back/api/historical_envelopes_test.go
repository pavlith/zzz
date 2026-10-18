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

func TestHistoricalKeyEnvelopes(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,v:=range []any{
  &models.User{ID:"owner",Email:"owner@invalid.test"},
  &models.User{ID:"stranger",Email:"stranger@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"owner",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:3},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"owner",CanRead:true},
  &models.Device{ID:"trusted",UserID:"owner",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:bytes.Repeat([]byte{2},32)},
  &models.Device{ID:"pending",UserID:"owner",Name:"Pending",VerifiedAt:&now,SigningPublicKey:bytes.Repeat([]byte{3},32),EncryptionPublicKey:bytes.Repeat([]byte{4},32)},
  &models.Device{ID:"other",UserID:"stranger",Name:"Other",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{5},32),EncryptionPublicKey:bytes.Repeat([]byte{6},32)},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 for i,dev:=range []string{"trusted","pending","other"} {
  record:=models.DeviceKeyEnvelope{ID:dev,VaultID:"v",DeviceID:dev,KeyEpoch:1,CryptoVersion:1,Ciphertext:bytes.Repeat([]byte{byte(i+1)},32)}
  if err:=db.Create(&record).Error;err!=nil{t.Fatal(err)}
 }
 tok,err:=auth.Issue(db,"owner",time.Hour);if err!=nil{t.Fatal(err)}
 stranger,err:=auth.Issue(db,"stranger",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 get:=func(token,query string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/v/key-envelopes/history"+query,nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 good:=get(tok,"?epoch=1")
 if good.Code!=200{t.Fatalf("history status: %d %s",good.Code,good.Body)}
 var rows []models.DeviceKeyEnvelope
 if err:=json.Unmarshal(good.Body.Bytes(),&rows);err!=nil{t.Fatal(err)}
 if len(rows)!=1||rows[0].DeviceID!="trusted"{t.Fatalf("leaked envelopes: %+v",rows)}
 if got:=get(tok,"?epoch=3").Code;got!=400{t.Fatalf("active epoch status: %d",got)}
 if got:=get(tok,"?epoch=4").Code;got!=400{t.Fatalf("future epoch status: %d",got)}
 if got:=get(stranger,"?epoch=1").Code;got!=404{t.Fatalf("unauthorized history: %d",got)}
}
