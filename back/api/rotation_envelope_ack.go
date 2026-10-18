package api

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func envelopeAckMessage(rotation models.VaultRotation,deviceID,envelopeHash string)[]byte {
 return []byte("zzz-rotation-envelope-ack-v1:"+rotation.VaultID+":"+rotation.ID+":"+rotation.ManifestSHA256+":"+deviceID+":"+envelopeHash)
}

func(a *API) acknowledgeRotationEnvelope(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 var input struct{DeviceID string `json:"device_id"`;EnvelopeSHA256 string `json:"envelope_sha256"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&input);err!=nil||input.DeviceID==""||len(input.EnvelopeSHA256)!=64||len(input.Signature)!=ed25519.SignatureSize {problem(w,400,"invalid_envelope_ack");return}
 if _,err:=hex.DecodeString(input.EnvelopeSHA256);err!=nil{problem(w,400,"invalid_envelope_hash");return}
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  var recipient models.RotationRecipient
  if err:=tx.First(&recipient,"rotation_id = ? AND device_id = ? AND user_id = ?",rotation.ID,input.DeviceID,userID).Error;err!=nil{return err}
  var device models.Device
  if err:=tx.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",input.DeviceID,userID).Error;err!=nil{return err}
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=recipient.SigningKeySHA256||hex.EncodeToString(encryption[:])!=recipient.EncryptionKeySHA256{return gorm.ErrRecordNotFound}
  var envelope models.DeviceKeyEnvelope
  if err:=tx.First(&envelope,"vault_id = ? AND device_id = ? AND key_epoch = ?",vaultID,device.ID,rotation.ToEpoch).Error;err!=nil{return err}
  digest:=sha256.Sum256(envelope.Envelope)
  if hex.EncodeToString(digest[:])!=input.EnvelopeSHA256{return gorm.ErrRecordNotFound}
  if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),envelopeAckMessage(rotation,device.ID,input.EnvelopeSHA256),input.Signature){return gorm.ErrRecordNotFound}
  return tx.Create(&models.RotationEnvelopeAck{RotationID:rotation.ID,DeviceID:device.ID,EnvelopeSHA256:input.EnvelopeSHA256,Signature:input.Signature}).Error
 })
 if err!=nil{problem(w,409,"envelope_ack_conflict");return}
 write(w,201,map[string]bool{"acknowledged":true})
}
