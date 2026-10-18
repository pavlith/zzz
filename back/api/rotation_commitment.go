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

func rotationCommitmentMessage(rotation models.VaultRotation,deviceID,commitment string)[]byte{
 return []byte("zzz-rotation-device-commitment-v1:"+rotation.VaultID+":"+rotation.ID+":"+rotation.ManifestSHA256+":"+deviceID+":"+commitment)
}

// submitRotationCommitment records a device-signed statement about the key it
// independently obtained. The server cannot prove actual possession of that key.
func(a *API) submitRotationCommitment(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 var input struct{DeviceID string `json:"device_id"`;ManifestSHA256 string `json:"manifest_sha256"`;KeyCommitment string `json:"key_commitment"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&input);err!=nil||input.DeviceID==""||len(input.ManifestSHA256)!=64||len(input.KeyCommitment)!=64||len(input.Signature)!=ed25519.SignatureSize {
  problem(w,400,"invalid_key_commitment");return
 }
 if _,err:=hex.DecodeString(input.ManifestSHA256);err!=nil{problem(w,400,"invalid_key_commitment");return}
 if _,err:=hex.DecodeString(input.KeyCommitment);err!=nil{problem(w,400,"invalid_key_commitment");return}
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  if rotation.ManifestSHA256!=input.ManifestSHA256{return gorm.ErrRecordNotFound}
  var recipient models.RotationRecipient
  if err:=tx.First(&recipient,"rotation_id = ? AND device_id = ? AND user_id = ?",rotation.ID,input.DeviceID,userID).Error;err!=nil{return err}
  var device models.Device
  if err:=tx.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",input.DeviceID,userID).Error;err!=nil{return err}
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=recipient.SigningKeySHA256||hex.EncodeToString(encryption[:])!=recipient.EncryptionKeySHA256{return gorm.ErrRecordNotFound}
  var recipients []models.RotationRecipient
  if err:=tx.Where("rotation_id = ?",rotation.ID).Order("device_id").Find(&recipients).Error;err!=nil{return err}
  if manifestDigest(rotation,recipients)!=rotation.ManifestSHA256{return gorm.ErrRecordNotFound}
  if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),rotationCommitmentMessage(rotation,device.ID,input.KeyCommitment),input.Signature){return gorm.ErrRecordNotFound}
  return tx.Create(&models.RotationCommitment{RotationID:rotation.ID,DeviceID:device.ID,ManifestSHA256:input.ManifestSHA256,KeyCommitment:input.KeyCommitment,Signature:input.Signature}).Error
 })
 if err!=nil{problem(w,409,"rotation_commitment_conflict");return}
 write(w,http.StatusCreated,map[string]bool{"recorded":true})
}
