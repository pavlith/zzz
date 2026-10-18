package candidatev1

import (
 "encoding/base64"
 "encoding/json"
 "strings"
 "testing"
)

func validFixture(t *testing.T) []byte {
 t.Helper()
 b64:=func(n int)string{return base64.RawURLEncoding.EncodeToString(make([]byte,n))}
 id:="12345678-1234-1234-1234-123456789abc"
 e:=Envelope{
  Protocol:Protocol,Suite:Suite,VaultID:id,DeviceID:id,RotationID:id,
  KeyEpoch:1,RecipientKeySHA256:b64(32),EphemeralPublicKey:b64(32),
  Nonce:b64(12),Ciphertext:b64(48),ManifestSHA256:b64(32),
  VaultKeyCommitment:b64(32),SignerDeviceID:id,Signature:b64(64),
 }
 data,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 return data
}

func TestParseValidFixture(t *testing.T){
 e,err:=Parse(validFixture(t))
 if err!=nil||e.KeyEpoch!=1{t.Fatalf("valid fixture rejected: %v",err)}
}

func TestParseRejectsMalformedFixtures(t *testing.T){
 fixture:=string(validFixture(t))
 invalid:=map[string]string{
  "duplicate field":strings.Replace(fixture,`"protocol":`,`"protocol":"zzz-e2ee-candidate-v1","protocol":`,1),
  "unknown field":strings.Replace(fixture,`"protocol":`,`"unknown":1,"protocol":`,1),
  "missing field":strings.Replace(fixture,`"protocol":"zzz-e2ee-candidate-v1",`,"",1),
  "unsupported suite":strings.Replace(fixture,Suite,"unknown",1),
  "negative epoch":strings.Replace(fixture,`"key_epoch":1`,`"key_epoch":-1`,1),
  "fractional epoch":strings.Replace(fixture,`"key_epoch":1`,`"key_epoch":1.5`,1),
  "epoch overflow":strings.Replace(fixture,`"key_epoch":1`,`"key_epoch":9007199254740992`,1),
  "invalid base64":strings.Replace(fixture,`"nonce":"`,`"nonce":"!`,1),
  "wrong length":strings.Replace(fixture,`"nonce":"AAAAAAAAAAAAAAAA"`,`"nonce":"AA"`,1),
  "trailing data":fixture+"{}",
 }
 for name,data:=range invalid{
  t.Run(name,func(t *testing.T){
   if _,err:=Parse([]byte(data));err==nil{t.Fatal("accepted malformed envelope")}
  })
 }
}
