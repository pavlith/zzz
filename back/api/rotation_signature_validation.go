package api

import (
 "crypto/ed25519"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type signatureValidation struct {
 Total int `json:"signature_count"`
 Valid int `json:"valid_signature_count"`
 InvalidDeviceIDs []string `json:"invalid_signer_device_ids"`
}

// validateRotationSignatures checks signatures against the current device keys and ACL.
// It does not claim that key envelopes are decryptable.
func validateRotationSignatures(db *gorm.DB,rotation models.VaultRotation)(signatureValidation,error){
 out:=signatureValidation{InvalidDeviceIDs:[]string{}}
 var signatures []models.RotationSignature
 if err:=db.Where("rotation_id = ?",rotation.ID).Order("device_id").Find(&signatures).Error;err!=nil{return out,err}
 out.Total=len(signatures)
 message:=rotationSignMessage(rotation)
 for _,signature:=range signatures{
  if signature.ManifestSHA256!=rotation.ManifestSHA256{
   out.InvalidDeviceIDs=append(out.InvalidDeviceIDs,signature.DeviceID);continue
  }
  var device models.Device
  err:=db.First(&device,"id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",signature.DeviceID).Error
  if err!=nil{
   if err==gorm.ErrRecordNotFound{out.InvalidDeviceIDs=append(out.InvalidDeviceIDs,signature.DeviceID);continue}
   return out,err
  }
  allowed,err:=acl.Allowed(db,device.UserID,rotation.VaultID,acl.Manage)
  if err!=nil{return out,err}
  if !allowed||!ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),message,signature.Signature){
   out.InvalidDeviceIDs=append(out.InvalidDeviceIDs,signature.DeviceID);continue
  }
  out.Valid++
 }
 return out,nil
}
