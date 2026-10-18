// Package e2ee implements a versioned client-side envelope format.
// The server must never receive unwrapped Vault keys.
package e2ee

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "hash"
 "io"
)

const Version = 1
var ErrInvalidEnvelope = errors.New("invalid e2ee envelope")

type Context struct {
 VaultID string `json:"vault_id"`
 RotationID string `json:"rotation_id"`
 DeviceID string `json:"device_id"`
 KeyEpoch uint64 `json:"key_epoch"`
}

type Envelope struct {
 Version uint32 `json:"version"`
 Context Context `json:"context"`
 RecipientKeySHA256 string `json:"recipient_key_sha256"`
 EphemeralPublicKey []byte `json:"ephemeral_public_key"`
 Nonce []byte `json:"nonce"`
 Ciphertext []byte `json:"ciphertext"`
}

func field(h hash.Hash,s []byte) {
 var size [8]byte
 binary.BigEndian.PutUint64(size[:],uint64(len(s)))
 _,_=h.Write(size[:]);_,_=h.Write(s)
}
func binding(ctx Context,fingerprint string) []byte {
 h:=sha256.New()
 field(h,[]byte("zzz-e2ee-envelope-aad-v1"))
 field(h,[]byte(ctx.VaultID))
 field(h,[]byte(ctx.RotationID))
 field(h,[]byte(ctx.DeviceID))
 var epoch [8]byte
 binary.BigEndian.PutUint64(epoch[:],ctx.KeyEpoch)
 field(h,epoch[:])
 field(h,[]byte(fingerprint))
 return h.Sum(nil)
}
func validContext(ctx Context)bool {
 return ctx.VaultID!=""&&ctx.DeviceID!=""&&ctx.KeyEpoch>0
}
func deriveKey(shared,info []byte)[]byte{
 // RFC5869 HKDF-SHA256, fixed all-zero salt.
 extract:=hmac.New(sha256.New,make([]byte,sha256.Size))
 _,_=extract.Write(shared)
 prk:=extract.Sum(nil)
 expand:=hmac.New(sha256.New,prk)
 _,_=expand.Write(info)
 _,_=expand.Write([]byte{1})
 return expand.Sum(nil)
}
func fingerprint(key []byte)string{
 sum:=sha256.Sum256(key)
 return hex.EncodeToString(sum[:])
}
func Wrap(vaultKey []byte,recipientPublic []byte,ctx Context)(Envelope,error){
 var out Envelope
 if len(vaultKey)!=32||!validContext(ctx){return out,ErrInvalidEnvelope}
 curve:=ecdh.X25519()
 recipient,err:=curve.NewPublicKey(recipientPublic)
 if err!=nil{return out,ErrInvalidEnvelope}
 ephemeral,err:=curve.GenerateKey(rand.Reader);if err!=nil{return out,err}
 shared,err:=ephemeral.ECDH(recipient);if err!=nil{return out,ErrInvalidEnvelope}
 fp:=fingerprint(recipientPublic)
 aad:=binding(ctx,fp)
 key:=deriveKey(shared,append([]byte("zzz-e2ee-aes256gcm-v1"),aad...))
 block,err:=aes.NewCipher(key);if err!=nil{return out,err}
 aead,err:=cipher.NewGCM(block);if err!=nil{return out,err}
 nonce:=make([]byte,aead.NonceSize())
 if _,err:=io.ReadFull(rand.Reader,nonce);err!=nil{return out,err}
 out=Envelope{Version:Version,Context:ctx,RecipientKeySHA256:fp,EphemeralPublicKey:ephemeral.PublicKey().Bytes(),Nonce:nonce}
 out.Ciphertext=aead.Seal(nil,nonce,vaultKey,aad)
 return out,nil
}
func Unwrap(envelope Envelope,recipientPrivate []byte,expected Context)([]byte,error){
 if envelope.Version!=Version||!validContext(expected)||envelope.Context!=expected||len(recipientPrivate)!=32||len(envelope.Nonce)!=12||len(envelope.Ciphertext)!=48{return nil,ErrInvalidEnvelope}
 curve:=ecdh.X25519()
 private,err:=curve.NewPrivateKey(recipientPrivate);if err!=nil{return nil,ErrInvalidEnvelope}
 if fingerprint(private.PublicKey().Bytes())!=envelope.RecipientKeySHA256{return nil,ErrInvalidEnvelope}
 ephemeral,err:=curve.NewPublicKey(envelope.EphemeralPublicKey);if err!=nil{return nil,ErrInvalidEnvelope}
 shared,err:=private.ECDH(ephemeral);if err!=nil{return nil,ErrInvalidEnvelope}
 aad:=binding(expected,envelope.RecipientKeySHA256)
 key:=deriveKey(shared,append([]byte("zzz-e2ee-aes256gcm-v1"),aad...))
 block,err:=aes.NewCipher(key);if err!=nil{return nil,err}
 aead,err:=cipher.NewGCM(block);if err!=nil{return nil,err}
 plaintext,err:=aead.Open(nil,envelope.Nonce,envelope.Ciphertext,aad)
 if err!=nil{return nil,ErrInvalidEnvelope}
 return plaintext,nil
}
