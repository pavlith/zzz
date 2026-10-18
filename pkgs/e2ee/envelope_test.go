package e2ee

import (
 "bytes"
 "crypto/ecdh"
 "crypto/rand"
 "encoding/json"
 "testing"
)

func TestWrapUnwrapAndContextBinding(t *testing.T){
 curve:=ecdh.X25519()
 recipient,err:=curve.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 other,err:=curve.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 original:=bytes.Repeat([]byte{0x42},32)
 ctx:=Context{VaultID:"vault",RotationID:"rotation",DeviceID:"device",KeyEpoch:2}
 envelope,err:=Wrap(original,recipient.PublicKey().Bytes(),ctx)
 if err!=nil{t.Fatal(err)}
 encoded,err:=json.Marshal(envelope);if err!=nil{t.Fatal(err)}
 var restored Envelope
 if err:=json.Unmarshal(encoded,&restored);err!=nil{t.Fatal(err)}
 plaintext,err:=Unwrap(restored,recipient.Bytes(),ctx)
 if err!=nil||!bytes.Equal(plaintext,original){t.Fatalf("round trip failed: %v",err)}
 if _,err:=Unwrap(envelope,other.Bytes(),ctx);err==nil{t.Fatal("wrong key accepted")}
 contexts:=[]Context{
  {VaultID:"other",RotationID:"rotation",DeviceID:"device",KeyEpoch:2},
  {VaultID:"vault",RotationID:"other",DeviceID:"device",KeyEpoch:2},
  {VaultID:"vault",RotationID:"rotation",DeviceID:"other",KeyEpoch:2},
  {VaultID:"vault",RotationID:"rotation",DeviceID:"device",KeyEpoch:3},
 }
 for _,changed:=range contexts{
  if _,err:=Unwrap(envelope,recipient.Bytes(),changed);err==nil{t.Fatalf("context substitution accepted: %+v",changed)}
 }
 mutated:=envelope
 mutated.Ciphertext=append([]byte(nil),envelope.Ciphertext...)
 mutated.Ciphertext[0]^=0xff
 if _,err:=Unwrap(mutated,recipient.Bytes(),ctx);err==nil{t.Fatal("tampered ciphertext accepted")}
 mutated=envelope
 mutated.EphemeralPublicKey=bytes.Repeat([]byte{0},32)
 if _,err:=Unwrap(mutated,recipient.Bytes(),ctx);err==nil{t.Fatal("low-order public key accepted")}
}

func TestRejectMalformedEnvelopes(t *testing.T){
 curve:=ecdh.X25519()
 recipient,err:=curve.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 ctx:=Context{VaultID:"v",DeviceID:"d",KeyEpoch:1}
 if _,err:=Wrap([]byte("short"),recipient.PublicKey().Bytes(),ctx);err==nil{t.Fatal("short key accepted")}
 if _,err:=Wrap(bytes.Repeat([]byte{1},32),[]byte("bad"),ctx);err==nil{t.Fatal("invalid recipient key accepted")}
 envelope,err:=Wrap(bytes.Repeat([]byte{1},32),recipient.PublicKey().Bytes(),ctx)
 if err!=nil{t.Fatal(err)}
 envelope.Version=2
 if _,err:=Unwrap(envelope,recipient.Bytes(),ctx);err==nil{t.Fatal("unsupported envelope version accepted")}
}
