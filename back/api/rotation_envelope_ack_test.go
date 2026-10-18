package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationEnvelopeAcknowledgement(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"u",Name:"Trusted",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{2},32),VerifiedAt:&now,TrustedAt:&now},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 request:=func(method,path string,body []byte)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewReader(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if r:=request("POST","/api/v1/vaults/v/rotation/prepare",nil);r.Code!=201{t.Fatalf("prepare: %d %s",r.Code,r.Body)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"vault_id = ?","v").Error;err!=nil{t.Fatal(err)}
 ciphertext:=bytes.Repeat([]byte{7},32)
 stage,_:=json.Marshal(map[string]any{"device_id":"d","key_epoch":2,"crypto_version":1,"ciphertext":ciphertext})
 if r:=request("POST","/api/v1/vaults/v/key-envelopes",stage);r.Code!=201{t.Fatalf("stage: %d %s",r.Code,r.Body)}
 digest:=sha256.Sum256(ciphertext)
 hash:=hex.EncodeToString(digest[:])
 payload:=func(signature []byte)[]byte{
  b,_:=json.Marshal(map[string]any{"device_id":"d","envelope_sha256":hash,"signature":signature});return b
 }
 route:="/api/v1/vaults/v/rotation/envelope-ack"
 if got:=request("POST",route,payload(bytes.Repeat([]byte{0},64))).Code;got==201{t.Fatal("invalid signature accepted")}
 signature:=ed25519.Sign(private,envelopeAckMessage(rotation,"d",hash))
 if got:=request("POST",route,payload(signature)).Code;got!=201{t.Fatalf("valid ack: %d",got)}
 pre:=request("GET","/api/v1/vaults/v/rotation/preflight",nil)
 if pre.Code!=200{t.Fatalf("preflight: %d",pre.Code)}
 var info struct{Valid int `json:"valid_envelope_acks"`;Required int `json:"required_envelope_acks"`;CanActivate bool `json:"can_activate"`}
 if err:=json.Unmarshal(pre.Body.Bytes(),&info);err!=nil{t.Fatal(err)}
 if info.Valid!=1||info.Required!=1||info.CanActivate{t.Fatalf("unexpected preflight: %+v",info)}
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ?","v","d").Update("ciphertext",bytes.Repeat([]byte{8},32)).Error;err!=nil{t.Fatal(err)}
 changed:=request("GET","/api/v1/vaults/v/rotation/preflight",nil)
 var after struct{Valid int `json:"valid_envelope_acks"`}
 if err:=json.Unmarshal(changed.Body.Bytes(),&after);err!=nil{t.Fatal(err)}
 if after.Valid!=0{t.Fatal("ack remained valid after ciphertext replacement")}
}
