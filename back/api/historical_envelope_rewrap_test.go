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

func TestSignedHistoricalEnvelopeRewrap(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,obj:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:3},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"source",UserID:"u",Name:"Source",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{1},32),VerifiedAt:&now,TrustedAt:&now},
  &models.Device{ID:"target",UserID:"u",Name:"Target",SigningPublicKey:bytes.Repeat([]byte{2},32),EncryptionPublicKey:bytes.Repeat([]byte{3},32),VerifiedAt:&now,TrustedAt:&now},
  &models.DeviceKeyEnvelope{ID:"old",VaultID:"v",DeviceID:"source",KeyEpoch:1,CryptoVersion:1,Ciphertext:bytes.Repeat([]byte{4},32)},
 }{if err:=db.Create(obj).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 ciphertext:=bytes.Repeat([]byte{5},32)
 sum:=sha256.Sum256(ciphertext)
 sign:=ed25519.Sign(key,historicalRewrapMessage("v",1,"source","target",hex.EncodeToString(sum[:])))
 call:=func(epoch uint64,sig []byte)*httptest.ResponseRecorder{
  input,_:=json.Marshal(map[string]any{"source_device_id":"source","device_id":"target","key_epoch":epoch,"crypto_version":1,"ciphertext":ciphertext,"signature":sig})
  req:=httptest.NewRequest("POST","/api/v1/vaults/v/key-envelopes/history/rewrap",bytes.NewReader(input))
  req.Header.Set("Authorization","Bearer "+token);req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();New(db).ServeHTTP(rec,req);return rec
 }
 if got:=call(1,bytes.Repeat([]byte{0},64)).Code;got==201{t.Fatal("forged signature accepted")}
 if got:=call(3,sign).Code;got==201{t.Fatal("active epoch accepted")}
 if got:=call(1,sign).Code;got!=201{t.Fatalf("valid rewrap rejected: %d",got)}
 if got:=call(1,sign).Code;got==201{t.Fatal("duplicate rewrap accepted")}
 var count int64
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?", "v","target",1).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("unexpected rewrap records: %d",count)}
}
