package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestSignedDeviceApproval(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.User{ID:"u",Email:"u@invalid.test"}).Error;err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 targetPub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,d:=range []models.Device{
  {ID:"approver",UserID:"u",Name:"Trusted",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{1},32),VerifiedAt:&now,TrustedAt:&now},
  {ID:"target",UserID:"u",Name:"New",SigningPublicKey:targetPub,EncryptionPublicKey:bytes.Repeat([]byte{2},32),VerifiedAt:&now},
 }{if err:=db.Create(&d).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 post:=func(path string,payload []byte)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST",path,bytes.NewReader(payload))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 endpoint:="/api/v1/devices/target"
 res:=post(endpoint+"/approval-challenge",[]byte(`{"approver_device_id":"approver"}`))
 if res.Code!=201{t.Fatalf("challenge: %d %s",res.Code,res.Body)}
 var challenge struct {ID string `json:"challenge_id"`;Nonce string `json:"nonce"`}
 if err:=json.Unmarshal(res.Body.Bytes(),&challenge);err!=nil{t.Fatal(err)}
 nonce,err:=base64.StdEncoding.DecodeString(challenge.Nonce);if err!=nil{t.Fatal(err)}
 message:=append([]byte("zzz-device-approval-v1:u:target:approver:"+challenge.ID+":"),targetPub...)
 message=append(message,bytes.Repeat([]byte{2},32)...)
 message=append(message,nonce...)
 payload,_:=json.Marshal(map[string]string{"challenge_id":challenge.ID,"signature":base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0},64))})
 if got:=post(endpoint+"/approve",payload).Code;got!=400{t.Fatalf("invalid signature: %d",got)}
 payload,_=json.Marshal(map[string]string{"challenge_id":challenge.ID,"signature":base64.StdEncoding.EncodeToString(ed25519.Sign(priv,message))})
 if got:=post(endpoint+"/approve",payload).Code;got!=200{t.Fatalf("approval: %d",got)}
 if got:=post(endpoint+"/approve",payload).Code;got==200{t.Fatal("replayed approval accepted")}
 var target models.Device
 if err:=db.First(&target,"id = ?","target").Error;err!=nil{t.Fatal(err)}
 if target.TrustedAt==nil{t.Fatal("target not trusted")}
}
