package candidatev1

import (
 "bytes"
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/rand"
 "testing"
)

func TestSignedRoundtrip(t *testing.T){
 recipient,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 pub,signer,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 ctx:=Context{VaultID:"12345678-1234-1234-1234-123456789abc",
 DeviceID:"22345678-1234-1234-1234-123456789abc",
 RotationID:"32345678-1234-1234-1234-123456789abc",
 SignerDeviceID:"42345678-1234-1234-1234-123456789abc",KeyEpoch:2}
 key:=bytes.Repeat([]byte{0x42},32)
 env,err:=Wrap(key,recipient.PublicKey().Bytes(),signer,ctx);if err!=nil{t.Fatal(err)}
 got,err:=Unwrap(env,recipient.Bytes(),pub,ctx)
 if err!=nil||!bytes.Equal(got,key){t.Fatalf("roundtrip failed: %v",err)}
 t.Run("tampered ciphertext",func(t *testing.T){
  changed:=env;changed.Ciphertext="A"+env.Ciphertext[1:]
  if _,err:=Unwrap(changed,recipient.Bytes(),pub,ctx);err==nil{t.Fatal("tampered ciphertext accepted")}
 })
 t.Run("wrong epoch",func(t *testing.T){
  changed:=ctx;changed.KeyEpoch++
  if _,err:=Unwrap(env,recipient.Bytes(),pub,changed);err==nil{t.Fatal("wrong epoch accepted")}
 })
 t.Run("wrong signer",func(t *testing.T){
  other,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  if _,err:=Unwrap(env,recipient.Bytes(),other,ctx);err==nil{t.Fatal("wrong signer accepted")}
 })
 t.Run("wrong recipient",func(t *testing.T){
  other,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  if _,err:=Unwrap(env,other.Bytes(),pub,ctx);err==nil{t.Fatal("wrong recipient accepted")}
 })
 t.Run("tampered commitment",func(t *testing.T){
  changed:=env;changed.VaultKeyCommitment="A"+env.VaultKeyCommitment[1:]
  if _,err:=Unwrap(changed,recipient.Bytes(),pub,ctx);err==nil{t.Fatal("tampered commitment accepted")}
 })
}
