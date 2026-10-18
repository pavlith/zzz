package api

import (
 "crypto/sha256"
 "encoding/hex"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type rotationValidation struct {
 Required int `json:"required_recipients"`
 Staged int `json:"staged_envelopes"`
 Missing []string `json:"missing_device_ids"`
 Invalid []string `json:"invalid_device_ids"`
 Unlisted []string `json:"unlisted_device_ids"`
 EpochCurrent bool `json:"epoch_current"`
 Complete bool `json:"complete"`
}

// validateRotation rechecks the manifest against live ACL, revocation and envelopes.
func validateRotation(db *gorm.DB,rotation models.VaultRotation)(rotationValidation,error){
 out:=rotationValidation{Missing:[]string{},Invalid:[]string{},Unlisted:[]string{}}
 var vault models.Vault
 if err:=db.First(&vault,"id = ?",rotation.VaultID).Error;err!=nil{return out,err}
 out.EpochCurrent=vault.KeyEpoch==rotation.FromEpoch
 var members []models.RotationRecipient
 if err:=db.Where("rotation_id = ?",rotation.ID).Order("device_id").Find(&members).Error;err!=nil{return out,err}
 out.Required=len(members)
 for _,member:=range members{
  var device models.Device
  err:=db.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",member.DeviceID,member.UserID).Error
  if err!=nil{
   if err==gorm.ErrRecordNotFound{out.Invalid=append(out.Invalid,member.DeviceID);continue}
   return out,err
  }
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=member.SigningKeySHA256||hex.EncodeToString(encryption[:])!=member.EncryptionKeySHA256{
   out.Invalid=append(out.Invalid,member.DeviceID);continue
  }
  allowed,err:=acl.Allowed(db,device.UserID,rotation.VaultID,acl.Read)
  if err!=nil{return out,err}
  if !allowed{out.Invalid=append(out.Invalid,member.DeviceID);continue}
  var n int64
  if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?",rotation.VaultID,device.ID,rotation.ToEpoch).Count(&n).Error;err!=nil{return out,err}
  if n!=1{out.Missing=append(out.Missing,device.ID)}else{out.Staged++}
 }
 var all []models.Device
 if err:=db.Where("verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL").Find(&all).Error;err!=nil{return out,err}
 known:=make(map[string]bool,len(members))
 for _,member:=range members{known[member.DeviceID]=true}
 for _,device:=range all{
  if known[device.ID]{continue}
  allowed,err:=acl.Allowed(db,device.UserID,rotation.VaultID,acl.Read)
  if err!=nil{return out,err}
  if allowed{out.Unlisted=append(out.Unlisted,device.ID)}
 }
 out.Complete=out.EpochCurrent&&out.Required>0&&len(out.Missing)==0&&len(out.Invalid)==0&&len(out.Unlisted)==0
 return out,nil
}
