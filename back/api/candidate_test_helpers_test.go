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

const fixtureVaultID = "12345678-1234-1234-1234-123456789abc"
const fixtureDeviceID = "22345678-1234-1234-1234-123456789abc"
const fixtureSignerID = "42345678-1234-1234-1234-123456789abc"

func candidateTestEnvelope(t *testing.T,vaultID,deviceID,rotationID,signerID string,epoch uint64,recipientPublic []byte,signer ed25519.PrivateKey,manifest [32]byte) []byte {
 t.Helper()
 e,err:=candidate.Wrap(bytes.Repeat([]byte{0x41},32),recipientPublic,signer,candidate.Context{
  VaultID:vaultID,DeviceID:deviceID,RotationID:rotationID,SignerDeviceID:signerID,KeyEpoch:epoch,ManifestSHA256:manifest,
 })
 if err!=nil{t.Fatal(err)}
 b,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 return b
}

func candidateTestKeys(t *testing.T)([]byte,ed25519.PrivateKey){
 t.Helper()
 recipient,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 _,signer,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return recipient.PublicKey().Bytes(),signer
}

func candidateTestRequest(t *testing.T,device string,epoch uint64,envelope []byte)string{
 t.Helper()
 b,err:=json.Marshal(map[string]any{"device_id":device,"key_epoch":epoch,"envelope":json.RawMessage(envelope)})
 if err!=nil{t.Fatal(err)}
 return string(b)
}

func candidateTestManifest() [32]byte {return sha256.Sum256([]byte("candidate-test-manifest"))}
