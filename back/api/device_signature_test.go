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

func TestDeviceSignatureAndReplay(t *testing.T) {
 db, err := database.Open(":memory:")
 if err != nil { t.Fatal(err) }
 if err = database.Migrate(db); err != nil { t.Fatal(err) }
 if err = db.Create(&models.User{ID:"user1",Email:"u1@example.test"}).Error; err != nil { t.Fatal(err) }
 token, err := auth.Issue(db,"user1",time.Hour)
 if err != nil { t.Fatal(err) }
 pub, priv, err := ed25519.GenerateKey(rand.Reader)
 if err != nil { t.Fatal(err) }
 if err = db.Create(&models.Device{ID:"device1",UserID:"user1",Name:"test",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{1},32)}).Error; err != nil { t.Fatal(err) }
 server := New(db)
 post := func(path string, payload []byte) *httptest.ResponseRecorder {
  req := httptest.NewRequest("POST",path,bytes.NewReader(payload))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  res := httptest.NewRecorder()
  server.ServeHTTP(res,req)
  return res
 }
 response := post("/api/v1/devices/device1/challenge",nil)
 if response.Code!=201 { t.Fatalf("challenge status %d: %s",response.Code,response.Body.String()) }
 var challenge struct {ChallengeID string `json:"challenge_id"`; Nonce string `json:"nonce"`}
 if err=json.Unmarshal(response.Body.Bytes(),&challenge);err!=nil {t.Fatal(err)}
 nonce,err:=base64.StdEncoding.DecodeString(challenge.Nonce)
 if err!=nil {t.Fatal(err)}
 message:=append([]byte("zzz-device-proof-v1:user1:device1:"+challenge.ChallengeID+":"),nonce...)
 body,err:=json.Marshal(map[string]string{"challenge_id":challenge.ChallengeID,"signature":base64.StdEncoding.EncodeToString(ed25519.Sign(priv,message))})
 if err!=nil {t.Fatal(err)}
 response=post("/api/v1/devices/device1/verify",body)
 if response.Code!=200 {t.Fatalf("verify status %d: %s",response.Code,response.Body.String())}
 response=post("/api/v1/devices/device1/verify",body)
 if response.Code!=409 {t.Fatalf("replay status %d",response.Code)}
}
