package candidatev1

import (
 "bytes"
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/json"
 "encoding/base64"
 "testing"
)

// Deterministic fixture material is public test data and must never be used
// for actual credentials. Repeated runs must produce identical wire bytes.
func TestDeterministicEnvelope(t *testing.T) {
 recipientSeed:=bytes.Repeat([]byte{0x21},32)
 recipient,err:=ecdh.X25519().NewPrivateKey(recipientSeed);if err!=nil{t.Fatal(err)}
 signingSeed:=bytes.Repeat([]byte{0x31},32)
 signer:=ed25519.NewKeyFromSeed(signingSeed)
 manifest:=sha256.Sum256([]byte("zzz-test-manifest-v1"))
 c:=Context{VaultID:"12345678-1234-1234-1234-123456789abc",
 DeviceID:"22345678-1234-1234-1234-123456789abc",
 RotationID:"32345678-1234-1234-1234-123456789abc",
 SignerDeviceID:"42345678-1234-1234-1234-123456789abc",
 KeyEpoch:3,ManifestSHA256:manifest}
 key:=bytes.Repeat([]byte{0x41},32)
 // crypto/ecdh GenerateKey may consume an additional random byte; provide ample
 // identical bytes to keep the fixture deterministic regardless of read offset.
 entropy:=bytes.Repeat([]byte{0x51},256)
 a,err:=wrapWithRandom(bytes.NewReader(entropy),key,recipient.PublicKey().Bytes(),signer,c)
 if err!=nil{t.Fatal(err)}
 b,err:=wrapWithRandom(bytes.NewReader(entropy),key,recipient.PublicKey().Bytes(),signer,c)
 if err!=nil{t.Fatal(err)}
 encodedA,err:=json.Marshal(a);if err!=nil{t.Fatal(err)}
 encodedB,err:=json.Marshal(b);if err!=nil{t.Fatal(err)}
 if !bytes.Equal(encodedA,encodedB){t.Fatal("deterministic fixture diverged")}
 recovered,err:=Unwrap(a,recipient.Bytes(),signer.Public().(ed25519.PublicKey),c)
 if err!=nil||!bytes.Equal(recovered,key){t.Fatalf("fixture decrypt: %v",err)}
 vector,err:=json.Marshal(map[string]any{
  "envelope":a,
  "recipient_private_key":base64.RawURLEncoding.EncodeToString(recipient.Bytes()),
  "recipient_public_key":base64.RawURLEncoding.EncodeToString(recipient.PublicKey().Bytes()),
  "signer_public_key":base64.RawURLEncoding.EncodeToString(signer.Public().(ed25519.PublicKey)),
  "vault_key":base64.RawURLEncoding.EncodeToString(key),
 })
 if err!=nil{t.Fatal(err)}
 t.Logf("CANDIDATE_V1_VECTOR=%s",vector)
}
