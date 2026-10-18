package api

import (
 "bytes"
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/json"
 "testing"

 candidate "github.com/pavlith/zzz/pkgs/e2ee/candidatev1"
)

func TestCandidateEnvelopeWriteBoundary(t *testing.T){
 recipient,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 _,signer,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 manifest:=sha256.Sum256([]byte("manifest"))
 c:=candidate.Context{
  VaultID:"12345678-1234-1234-1234-123456789abc",
  DeviceID:"22345678-1234-1234-1234-123456789abc",
  RotationID:"32345678-1234-1234-1234-123456789abc",
  SignerDeviceID:"42345678-1234-1234-1234-123456789abc",
  KeyEpoch:2,ManifestSHA256:manifest,
 }
 e,err:=candidate.Wrap(bytes.Repeat([]byte{7},32),recipient.PublicKey().Bytes(),signer,c)
 if err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 got,err:=decodeCandidateEnvelopeRequest(raw,c.VaultID,c.DeviceID,c.KeyEpoch)
 if err!=nil{t.Fatal(err)}
 if !bytes.Equal(raw,got){t.Fatal("canonical candidate envelope mismatch")}
 for _,tc:=range []struct{name string;payload []byte;vault,device string;epoch uint64}{
  {"legacy opaque",[]byte(`{"crypto_version":1,"ciphertext":"AA"}`),c.VaultID,c.DeviceID,c.KeyEpoch},
  {"duplicate",bytes.Replace(raw,[]byte(`"protocol":`),[]byte(`"protocol":"zzz-e2ee-candidate-v1","protocol":`),1),c.VaultID,c.DeviceID,c.KeyEpoch},
  {"wrong vault",raw,"52345678-1234-1234-1234-123456789abc",c.DeviceID,c.KeyEpoch},
  {"wrong device",raw,c.VaultID,"62345678-1234-1234-1234-123456789abc",c.KeyEpoch},
  {"wrong epoch",raw,c.VaultID,c.DeviceID,c.KeyEpoch+1},
 }{
  t.Run(tc.name,func(t *testing.T){
   if _,err:=decodeCandidateEnvelopeRequest(tc.payload,tc.vault,tc.device,tc.epoch);err==nil{t.Fatal("invalid envelope accepted")}
  })
 }
}
