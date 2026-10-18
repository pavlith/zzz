package candidatev1

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/ecdh"
 "crypto/ed25519"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/binary"
 "encoding/json"
 "io"
)

// Context contains independently authorized metadata. A caller must verify
// manifest membership and signing-device identity outside this package.
type Context struct {
 VaultID string
 DeviceID string
 RotationID string
 SignerDeviceID string
 KeyEpoch uint64
 ManifestSHA256 [32]byte
}

func encoded(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func domain(label string, payload []byte) []byte {
 prefix:=[]byte("zzz/e2ee/candidate-v1/"+label)
 out:=make([]byte,0,len(prefix)+5+len(payload))
 out=append(out,prefix...);out=append(out,0)
 var size [4]byte;binary.BigEndian.PutUint32(size[:],uint32(len(payload)))
 out=append(out,size[:]...);return append(out,payload...)
}
func canonical(fields map[string]any) ([]byte,error) {
 // Flat ASCII keys and string/uint64 values: encoding/json emits the same
 // lexicographic ordering and primitive encodings as JCS for this subset.
 return json.Marshal(fields)
}
func metadata(e Envelope, includeCommitment bool) map[string]any {
 m:=map[string]any{
 "protocol":e.Protocol,"suite":e.Suite,"vault_id":e.VaultID,
 "device_id":e.DeviceID,"rotation_id":e.RotationID,
 "key_epoch":e.KeyEpoch,"recipient_key_sha256":e.RecipientKeySHA256,
 "ephemeral_public_key":e.EphemeralPublicKey,
 "manifest_sha256":e.ManifestSHA256,"signer_device_id":e.SignerDeviceID,
 }
 if includeCommitment {m["vault_key_commitment"]=e.VaultKeyCommitment}
 return m
}
func signed(e Envelope) ([]byte,error) {
 m:=metadata(e,true)
 m["nonce"]=e.Nonce;m["ciphertext"]=e.Ciphertext
 b,err:=canonical(m);if err!=nil{return nil,err}
 return domain("signed-envelope",b),nil
}
func commitment(e Envelope, vaultKey []byte)([32]byte,error){
 var zero [32]byte
 if len(vaultKey)!=32{return zero,ErrInvalid}
 b,err:=canonical(map[string]any{"protocol":e.Protocol,"vault_id":e.VaultID,
 "key_epoch":e.KeyEpoch,"manifest_sha256":e.ManifestSHA256,"key":encoded(vaultKey)})
 if err!=nil{return zero,err}
 return sha256.Sum256(domain("vault-key-commitment",b)),nil
}
func hkdf(shared,info []byte) []byte {
 extract:=hmac.New(sha256.New,make([]byte,32));extract.Write(shared)
 expand:=hmac.New(sha256.New,extract.Sum(nil));expand.Write(info);expand.Write([]byte{1})
 return expand.Sum(nil)
}
func contextMatches(e Envelope,c Context)bool{
 return e.VaultID==c.VaultID&&e.DeviceID==c.DeviceID&&
 e.RotationID==c.RotationID&&e.SignerDeviceID==c.SignerDeviceID&&
 e.KeyEpoch==c.KeyEpoch&&e.ManifestSHA256==encoded(c.ManifestSHA256[:])
}
func Wrap(vaultKey, recipientPublic []byte, signerPrivate ed25519.PrivateKey, c Context)(Envelope,error){
 var e Envelope
 if len(vaultKey)!=32||len(recipientPublic)!=32||len(signerPrivate)!=ed25519.PrivateKeySize{return e,ErrInvalid}
 curve:=ecdh.X25519()
 recipient,err:=curve.NewPublicKey(recipientPublic);if err!=nil{return e,ErrInvalid}
 ephemeral,err:=curve.GenerateKey(rand.Reader);if err!=nil{return e,err}
 shared,err:=ephemeral.ECDH(recipient);if err!=nil{return e,ErrInvalid}
 fingerprint:=sha256.Sum256(recipientPublic)
 e=Envelope{Protocol:Protocol,Suite:Suite,VaultID:c.VaultID,DeviceID:c.DeviceID,
 RotationID:c.RotationID,SignerDeviceID:c.SignerDeviceID,KeyEpoch:c.KeyEpoch,
 RecipientKeySHA256:encoded(fingerprint[:]),EphemeralPublicKey:encoded(ephemeral.PublicKey().Bytes()),
 ManifestSHA256:encoded(c.ManifestSHA256[:])}
 if !contextMatches(e,c){return Envelope{},ErrInvalid}
 cm,err:=commitment(e,vaultKey);if err!=nil{return Envelope{},err}
 e.VaultKeyCommitment=encoded(cm[:])
 infoFields:=metadata(e,false)
 infoBytes,err:=canonical(infoFields);if err!=nil{return Envelope{},err}
 aadBytes,err:=canonical(metadata(e,true));if err!=nil{return Envelope{},err}
 key:=hkdf(shared,domain("envelope-kek",infoBytes))
 block,err:=aes.NewCipher(key);if err!=nil{return Envelope{},err}
 aead,err:=cipher.NewGCM(block);if err!=nil{return Envelope{},err}
 nonce:=make([]byte,12);if _,err=io.ReadFull(rand.Reader,nonce);err!=nil{return Envelope{},err}
 e.Nonce=encoded(nonce)
 e.Ciphertext=encoded(aead.Seal(nil,nonce,vaultKey,domain("recipient-envelope-aad",aadBytes)))
 message,err:=signed(e);if err!=nil{return Envelope{},err}
 e.Signature=encoded(ed25519.Sign(signerPrivate,message))
 return e,e.Validate()
}
func Unwrap(e Envelope,recipientPrivate []byte,expectedSigner ed25519.PublicKey,c Context)([]byte,error){
 if e.Validate()!=nil||!contextMatches(e,c)||len(recipientPrivate)!=32||len(expectedSigner)!=ed25519.PublicKeySize{return nil,ErrInvalid}
 signature,_:=base64.RawURLEncoding.DecodeString(e.Signature)
 message,err:=signed(e);if err!=nil||!ed25519.Verify(expectedSigner,message,signature){return nil,ErrInvalid}
 curve:=ecdh.X25519()
 private,err:=curve.NewPrivateKey(recipientPrivate);if err!=nil{return nil,ErrInvalid}
 fingerprint:=sha256.Sum256(private.PublicKey().Bytes())
 if subtle.ConstantTimeCompare([]byte(e.RecipientKeySHA256),[]byte(encoded(fingerprint[:])))!=1{return nil,ErrInvalid}
 ephemeralBytes,_:=base64.RawURLEncoding.DecodeString(e.EphemeralPublicKey)
 ephemeral,err:=curve.NewPublicKey(ephemeralBytes);if err!=nil{return nil,ErrInvalid}
 shared,err:=private.ECDH(ephemeral);if err!=nil{return nil,ErrInvalid}
 infoBytes,err:=canonical(metadata(e,false));if err!=nil{return nil,ErrInvalid}
 aadBytes,err:=canonical(metadata(e,true));if err!=nil{return nil,ErrInvalid}
 key:=hkdf(shared,domain("envelope-kek",infoBytes))
 block,err:=aes.NewCipher(key);if err!=nil{return nil,ErrInvalid}
 aead,err:=cipher.NewGCM(block);if err!=nil{return nil,ErrInvalid}
 nonce,_:=base64.RawURLEncoding.DecodeString(e.Nonce)
 ciphertext,_:=base64.RawURLEncoding.DecodeString(e.Ciphertext)
 plain,err:=aead.Open(nil,nonce,ciphertext,domain("recipient-envelope-aad",aadBytes))
 if err!=nil{return nil,ErrInvalid}
 cm,err:=commitment(e,plain);if err!=nil{return nil,ErrInvalid}
 expectedCM,_:=base64.RawURLEncoding.DecodeString(e.VaultKeyCommitment)
 if subtle.ConstantTimeCompare(cm[:],expectedCM)!=1{return nil,ErrInvalid}
 return plain,nil
}

