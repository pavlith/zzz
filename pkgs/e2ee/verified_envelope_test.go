package e2ee

import (
 "bytes"
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/rand"
 "strings"
 "testing"
)

func TestVerifiedEnvelopeIdentityAndKeyCommitment(t *testing.T){
 device,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 signerPublic,signerPrivate,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 impostorPublic,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 ctx:=Context{VaultID:"vault",RotationID:"rotation",DeviceID:"device",KeyEpoch:2}
 manifest:=strings.Repeat("a",64)
 key:=bytes.Repeat([]byte{5},32)
 wrapped,err:=SignWrappedKey(key,device.PublicKey().Bytes(),ctx,manifest,signerPrivate)
 if err!=nil{t.Fatal(err)}
 got,err:=OpenVerifiedKey(wrapped,device.Bytes(),ctx,manifest,signerPublic)
 if err!=nil||!bytes.Equal(got,key){t.Fatalf("verified unwrap: %v",err)}
 if _,err:=OpenVerifiedKey(wrapped,device.Bytes(),ctx,manifest,impostorPublic);err==nil{t.Fatal("wrong signer accepted")}
 if _,err:=OpenVerifiedKey(wrapped,device.Bytes(),ctx,strings.Repeat("b",64),signerPublic);err==nil{t.Fatal("wrong manifest accepted")}
 changed:=wrapped
 changed.Envelope.Ciphertext=append([]byte(nil),wrapped.Envelope.Ciphertext...)
 changed.Envelope.Ciphertext[0]^=1
 if _,err:=OpenVerifiedKey(changed,device.Bytes(),ctx,manifest,signerPublic);err==nil{t.Fatal("modified ciphertext accepted")}
 changed=wrapped
 changed.KeyCommitment=strings.Repeat("f",64)
 if _,err:=OpenVerifiedKey(changed,device.Bytes(),ctx,manifest,signerPublic);err==nil{t.Fatal("modified commitment accepted")}
 changed=wrapped
 changed.Signature=append([]byte(nil),wrapped.Signature...)
 changed.Signature[0]^=1
 if _,err:=OpenVerifiedKey(changed,device.Bytes(),ctx,manifest,signerPublic);err==nil{t.Fatal("forged signature accepted")}
 changedCtx:=ctx;changedCtx.DeviceID="other"
 if _,err:=OpenVerifiedKey(wrapped,device.Bytes(),changedCtx,manifest,signerPublic);err==nil{t.Fatal("changed recipient accepted")}
}
