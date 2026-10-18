// Package candidatev1 validates the proposed, unapproved E2EE envelope wire format.
// Parsing alone neither authenticates a device nor makes ciphertext safe to decrypt.
package candidatev1

import (
 "bytes"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "regexp"
)

const Protocol = "zzz-e2ee-candidate-v1"
const Suite = "X25519-HKDF-SHA256-AES256GCM-Ed25519"
var ErrInvalid = errors.New("invalid candidate envelope")
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Envelope struct {
 Protocol string `json:"protocol"`
 Suite string `json:"suite"`
 VaultID string `json:"vault_id"`
 DeviceID string `json:"device_id"`
 RotationID string `json:"rotation_id"`
 KeyEpoch uint64 `json:"key_epoch"`
 RecipientKeySHA256 string `json:"recipient_key_sha256"`
 EphemeralPublicKey string `json:"ephemeral_public_key"`
 Nonce string `json:"nonce"`
 Ciphertext string `json:"ciphertext"`
 ManifestSHA256 string `json:"manifest_sha256"`
 VaultKeyCommitment string `json:"vault_key_commitment"`
 SignerDeviceID string `json:"signer_device_id"`
 Signature string `json:"signature"`
}

func exactBytes(value string, expected int) bool {
 b,err:=base64.RawURLEncoding.Strict().DecodeString(value)
 return err==nil && len(b)==expected && base64.RawURLEncoding.EncodeToString(b)==value
}
func (e Envelope) Validate() error {
 if e.Protocol!=Protocol || e.Suite!=Suite ||
 !uuidPattern.MatchString(e.VaultID) || !uuidPattern.MatchString(e.DeviceID) ||
 !uuidPattern.MatchString(e.RotationID) || !uuidPattern.MatchString(e.SignerDeviceID) ||
 e.KeyEpoch==0 || e.KeyEpoch>9007199254740991 ||
 !exactBytes(e.RecipientKeySHA256,32) || !exactBytes(e.EphemeralPublicKey,32) ||
 !exactBytes(e.Nonce,12) || !exactBytes(e.Ciphertext,48) ||
 !exactBytes(e.ManifestSHA256,32) || !exactBytes(e.VaultKeyCommitment,32) ||
 !exactBytes(e.Signature,64) {return ErrInvalid}
 return nil
}

// Parse requires precisely the specified top-level keys and rejects trailing data.
// The schema is flat: every member must have a string value except key_epoch.
func Parse(data []byte)(Envelope,error){
 var e Envelope
 dec:=json.NewDecoder(bytes.NewReader(data))
 first,err:=dec.Token();if err!=nil||first!=json.Delim('{'){return e,ErrInvalid}
 allowed:=map[string]bool{"protocol":true,"suite":true,"vault_id":true,"device_id":true,
 "rotation_id":true,"key_epoch":true,"recipient_key_sha256":true,
 "ephemeral_public_key":true,"nonce":true,"ciphertext":true,
 "manifest_sha256":true,"vault_key_commitment":true,"signer_device_id":true,"signature":true}
 fields:=make(map[string]json.RawMessage,len(allowed))
 for dec.More(){
  keyToken,err:=dec.Token();if err!=nil{return e,ErrInvalid}
  key,ok:=keyToken.(string);if !ok||!allowed[key]{return e,ErrInvalid}
  if _,duplicate:=fields[key];duplicate{return e,ErrInvalid}
  var raw json.RawMessage
  if dec.Decode(&raw)!=nil{return e,ErrInvalid}
  if key=="key_epoch"{
   if len(raw)==0||raw[0]<'0'||raw[0]>'9'{return e,ErrInvalid}
  }else if len(raw)==0||raw[0]!='"'{return e,ErrInvalid}
  fields[key]=raw
 }
 if len(fields)!=len(allowed){return e,ErrInvalid}
 last,err:=dec.Token();if err!=nil||last!=json.Delim('}') {return e,ErrInvalid}
 if _,err=dec.Token();err!=io.EOF{return e,ErrInvalid}
 normalized,err:=json.Marshal(fields);if err!=nil{return e,ErrInvalid}
 if json.Unmarshal(normalized,&e)!=nil{return e,ErrInvalid}
 return e,e.Validate()
}
