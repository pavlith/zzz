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

func TestHistoricalKeyEnvelopes(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 trustedKey,signer:=candidateTestKeys(t)
 pendingKey,_:=candidateTestKeys(t)
 otherKey,_:=candidateTestKeys(t)
 trustedID:=fixtureDeviceID
 pendingID:="52345678-1234-1234-1234-123456789abc"
 otherID:="62345678-1234-1234-1234-123456789abc"
 for _,v:=range []any{
  &models.User{ID:"owner",Email:"owner@invalid.test"},
  &models.User{ID:"stranger",Email:"stranger@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"owner",Role:"owner"},
  &models.Vault{ID:fixtureVaultID,WorkspaceID:"w",Name:"Vault",KeyEpoch:3},
  &models.VaultPermission{ID:"p",VaultID:fixtureVaultID,PrincipalType:"user",PrincipalID:"owner",CanRead:true},
  &models.Device{ID:trustedID,UserID:"owner",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:trustedKey},
  &models.Device{ID:pendingID,UserID:"owner",Name:"Pending",VerifiedAt:&now,SigningPublicKey:bytes.Repeat([]byte{3},32),EncryptionPublicKey:pendingKey},
  &models.Device{ID:otherID,UserID:"stranger",Name:"Other",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{5},32),EncryptionPublicKey:otherKey},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 for i,dev:=range []string{trustedID,pendingID,otherID} {
  public:=[][]byte{trustedKey,pendingKey,otherKey}[i]
  wire:=candidateTestEnvelope(t,fixtureVaultID,dev,fixtureRotationID,fixtureSignerID,1,public,signer,candidateTestManifest())
  record:=models.DeviceKeyEnvelope{ID:dev,VaultID:fixtureVaultID,DeviceID:dev,KeyEpoch:1,CryptoVersion:1,Ciphertext:wire}
  if err:=db.Create(&record).Error;err!=nil{t.Fatal(err)}
 }
 tok,err:=auth.Issue(db,"owner",time.Hour);if err!=nil{t.Fatal(err)}
 stranger,err:=auth.Issue(db,"stranger",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 get:=func(token,query string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("GET","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes/history"+query,nil)
  req.Header.Set("Authorization","Bearer "+token)
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 good:=get(tok,"?epoch=1")
 if good.Code!=200{t.Fatalf("history status: %d %s",good.Code,good.Body)}
 var rows []keyEnvelopeResponse
 if err:=json.Unmarshal(good.Body.Bytes(),&rows);err!=nil{t.Fatal(err)}
 if len(rows)!=1||rows[0].DeviceID!=trustedID{t.Fatalf("leaked envelopes: %+v",rows)}
 if len(rows[0].Envelope)==0{t.Fatal("missing candidate envelope")}
 var raw []map[string]json.RawMessage
 if err:=json.Unmarshal(good.Body.Bytes(),&raw);err!=nil{t.Fatal(err)}
 if _,ok:=raw[0]["ciphertext"];ok{t.Fatal("legacy ciphertext leaked into response")}
 if _,ok:=raw[0]["crypto_version"];ok{t.Fatal("legacy crypto_version leaked into response")}
 if got:=get(tok,"?epoch=3").Code;got!=400{t.Fatalf("active epoch status: %d",got)}
 if got:=get(tok,"?epoch=4").Code;got!=400{t.Fatalf("future epoch status: %d",got)}
 if got:=get(stranger,"?epoch=1").Code;got!=404{t.Fatalf("unauthorized history: %d",got)}
}
