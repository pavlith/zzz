package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/ecdh"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 candidate "github.com/pavlith/zzz/pkgs/e2ee/candidatev1"
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
 recipient,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 sourceID:="42345678-1234-1234-1234-123456789abc"
 targetID:=fixtureDeviceID
 for _,obj:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:fixtureVaultID,WorkspaceID:"w",Name:"V",KeyEpoch:3},
  &models.VaultPermission{ID:"p",VaultID:fixtureVaultID,PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:sourceID,UserID:"u",Name:"Source",SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{1},32),VerifiedAt:&now,TrustedAt:&now},
  &models.Device{ID:targetID,UserID:"u",Name:"Target",SigningPublicKey:bytes.Repeat([]byte{2},32),EncryptionPublicKey:recipient.PublicKey().Bytes(),VerifiedAt:&now,TrustedAt:&now},
  &models.DeviceKeyEnvelope{ID:"old",VaultID:fixtureVaultID,DeviceID:sourceID,KeyEpoch:1,CryptoVersion:1,Envelope:bytes.Repeat([]byte{4},32)},
 }{if err:=db.Create(obj).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 envelope,err:=candidate.Wrap(bytes.Repeat([]byte{5},32),recipient.PublicKey().Bytes(),key,candidate.Context{VaultID:fixtureVaultID,DeviceID:targetID,RotationID:fixtureRotationID,SignerDeviceID:sourceID,KeyEpoch:1,ManifestSHA256:candidateTestManifest()});if err!=nil{t.Fatal(err)}
 ciphertext,err:=json.Marshal(envelope);if err!=nil{t.Fatal(err)}
 sum:=sha256.Sum256(ciphertext)
 sign:=ed25519.Sign(key,historicalRewrapMessage(fixtureVaultID,1,sourceID,targetID,hex.EncodeToString(sum[:])))
 call:=func(epoch uint64,sig []byte)*httptest.ResponseRecorder{
  input,_:=json.Marshal(map[string]any{"source_device_id":sourceID,"device_id":targetID,"key_epoch":epoch,"envelope":envelope,"signature":sig})
  req:=httptest.NewRequest("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes/history/rewrap",bytes.NewReader(input))
  req.Header.Set("Authorization","Bearer "+token);req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();New(db).ServeHTTP(rec,req);return rec
 }
 if got:=call(1,bytes.Repeat([]byte{0},64)).Code;got==201{t.Fatal("forged signature accepted")}
 if got:=call(3,sign).Code;got==201{t.Fatal("active epoch accepted")}
 if got:=call(1,sign).Code;got!=201{t.Fatalf("valid rewrap rejected: %d",got)}
 if got:=call(1,sign).Code;got==201{t.Fatal("duplicate rewrap accepted")}
 var count int64
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?", fixtureVaultID,targetID,1).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("unexpected rewrap records: %d",count)}
}
