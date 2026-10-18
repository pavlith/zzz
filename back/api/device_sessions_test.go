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

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestSignedDeviceSession(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Device{ID:"d",UserID:"u",Name:"Laptop",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{1},32),VerifiedAt:&now,TrustedAt:&now},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 server:=New(db)
 post:=func(path string,body []byte)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST",path,bytes.NewReader(body))
  req.Header.Set("Content-Type","application/json")
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 result:=post("/api/v1/auth/device/challenge",[]byte(`{"device_id":"d"}`))
 if result.Code!=201{t.Fatalf("challenge status: %d",result.Code)}
 var challenge struct{ID string `json:"challenge_id"`;Nonce string `json:"nonce"`}
 if err:=json.Unmarshal(result.Body.Bytes(),&challenge);err!=nil{t.Fatal(err)}
 nonce,err:=base64.StdEncoding.DecodeString(challenge.Nonce);if err!=nil{t.Fatal(err)}
 signed:=append([]byte("zzz-device-session-v1:u:d:"+challenge.ID+":"),nonce...)
 body,_:=json.Marshal(map[string]string{"device_id":"d","challenge_id":challenge.ID,"signature":base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0},64))})
 if code:=post("/api/v1/auth/device/session",body).Code;code!=400{t.Fatalf("invalid signature: %d",code)}
 body,_=json.Marshal(map[string]string{"device_id":"d","challenge_id":challenge.ID,"signature":base64.StdEncoding.EncodeToString(ed25519.Sign(priv,signed))})
 response:=post("/api/v1/auth/device/session",body)
 if response.Code!=201{t.Fatalf("valid session: %d %s",response.Code,response.Body)}
 var session struct{Token string `json:"token"`}
 if err:=json.Unmarshal(response.Body.Bytes(),&session);err!=nil{t.Fatal(err)}
 if session.Token==""{t.Fatal("empty token")}
 if code:=post("/api/v1/auth/device/session",body).Code;code==201{t.Fatal("challenge replay accepted")}
 req:=httptest.NewRequest("GET","/api/v1/me",nil)
 req.Header.Set("Authorization","Bearer "+session.Token)
 ok:=httptest.NewRecorder();server.ServeHTTP(ok,req)
 if ok.Code!=200{t.Fatalf("bound session status %d",ok.Code)}
 if err:=db.Model(&models.Device{}).Where("id = ?","d").Update("revoked_at",now).Error;err!=nil{t.Fatal(err)}
 denied:=httptest.NewRecorder();server.ServeHTTP(denied,req)
 if denied.Code!=401{t.Fatalf("revoked session status %d",denied.Code)}
}
