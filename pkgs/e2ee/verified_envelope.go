package e2ee

import (
 "crypto/ed25519"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/hex"
 "errors"
)

var ErrKeyCommitment = errors.New("e2ee key commitment mismatch")

// VerifiedEnvelope is an envelope accompanied by an authenticated key commitment.
// KeyCommitment is NOT a substitute for authenticating the signing device.
type VerifiedEnvelope struct {
 Envelope Envelope `json:"envelope"`
 ManifestSHA256 string `json:"manifest_sha256"`
 KeyCommitment string `json:"key_commitment"`
 SignerPublicKey []byte `json:"signer_public_key"`
 Signature []byte `json:"signature"`
}

func commitment(key []byte,manifest string)string{
 h:=sha256.New()
 field(h,[]byte("zzz-vault-key-commitment-v1"))
 field(h,[]byte(manifest))
 field(h,key)
 return hex.EncodeToString(h.Sum(nil))
}

func verifiedMessage(envelope Envelope,manifest,commit string)[]byte{
 h:=sha256.New()
 field(h,[]byte("zzz-verified-envelope-v1"))
 field(h,[]byte(manifest))
 field(h,[]byte(commit))
 field(h,binding(envelope.Context,envelope.RecipientKeySHA256))
 field(h,envelope.EphemeralPublicKey)
 field(h,envelope.Nonce)
 field(h,envelope.Ciphertext)
 return h.Sum(nil)
}

// SignWrappedKey signs the encrypted contents and a commitment to the intended key.
func SignWrappedKey(key,recipient []byte,ctx Context,manifest string,signer ed25519.PrivateKey)(VerifiedEnvelope,error){
 var out VerifiedEnvelope
 if len(manifest)!=64||len(signer)!=ed25519.PrivateKeySize{return out,ErrInvalidEnvelope}
 if _,err:=hex.DecodeString(manifest);err!=nil{return out,ErrInvalidEnvelope}
 envelope,err:=Wrap(key,recipient,ctx);if err!=nil{return out,err}
 out=VerifiedEnvelope{Envelope:envelope,ManifestSHA256:manifest,KeyCommitment:commitment(key,manifest),SignerPublicKey:append([]byte(nil),signer.Public().(ed25519.PublicKey)...)}
 out.Signature=ed25519.Sign(signer,verifiedMessage(out.Envelope,manifest,out.KeyCommitment))
 return out,nil
}

// OpenVerifiedKey requires a separately authenticated expected signing key and
// manifest digest. Otherwise a self-signed forged envelope would be accepted.
func OpenVerifiedKey(v VerifiedEnvelope,private []byte,ctx Context,expectedManifest string,expectedSigner ed25519.PublicKey)([]byte,error){
 if len(expectedSigner)!=ed25519.PublicKeySize||len(v.SignerPublicKey)!=ed25519.PublicKeySize||len(v.Signature)!=ed25519.SignatureSize||len(expectedManifest)!=64{return nil,ErrInvalidEnvelope}
 if subtle.ConstantTimeCompare([]byte(v.ManifestSHA256),[]byte(expectedManifest))!=1||subtle.ConstantTimeCompare(v.SignerPublicKey,expectedSigner)!=1{return nil,ErrInvalidEnvelope}
 if !ed25519.Verify(expectedSigner,verifiedMessage(v.Envelope,v.ManifestSHA256,v.KeyCommitment),v.Signature){return nil,ErrInvalidEnvelope}
 key,err:=Unwrap(v.Envelope,private,ctx);if err!=nil{return nil,err}
 expected:=commitment(key,expectedManifest)
 if subtle.ConstantTimeCompare([]byte(expected),[]byte(v.KeyCommitment))!=1{return nil,ErrKeyCommitment}
 return key,nil
}
