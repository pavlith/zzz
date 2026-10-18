package api

import (
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type rotationValidation struct {
 Required int `json:"required_recipients"`
 Staged int `json:"staged_envelopes"`
 Missing []string `json:"missing_device_ids"`
 Invalid []string `json:"invalid_device_ids"`
 EpochCurrent bool `json:"epoch_current"`
 Complete bool `json:"complete"`
}

// validateRotation rechecks the manifest against live ACL, revocation and envelopes.
func validateRotation(db *gorm.DB,rotation models.VaultRotation)(rotationValidation,error){
 out:=rotationValidation{Missing:[]string{},Invalid:[]string{}}
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
  allowed,err:=acl.Allowed(db,device.UserID,rotation.VaultID,acl.Read)
  if err!=nil{return out,err}
  if !allowed{out.Invalid=append(out.Invalid,member.DeviceID);continue}
  var n int64
  if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?",rotation.VaultID,device.ID,rotation.ToEpoch).Count(&n).Error;err!=nil{return out,err}
  if n!=1{out.Missing=append(out.Missing,device.ID)}else{out.Staged++}
 }
 out.Complete=out.EpochCurrent&&out.Required>0&&len(out.Missing)==0&&len(out.Invalid)==0
 return out,nil
}
