package api

import (
 "net/http"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// prepareRotation reserves a target epoch. It does not activate a new key.
func(a *API) prepareRotation(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 var out models.VaultRotation
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  var pending int64
  if err:=tx.Model(&models.VaultRotation{}).Where("vault_id = ? AND status = ?",vaultID,"prepared").Count(&pending).Error;err!=nil{return err}
  if pending!=0{return errRotationPending}
  out=models.VaultRotation{ID:uuid.NewString(),VaultID:vaultID,FromEpoch:vault.KeyEpoch,ToEpoch:vault.KeyEpoch+1,Status:"prepared"}
  if err:=tx.Create(&out).Error;err!=nil{return err}
  var devices []models.Device
  if err:=tx.Where("verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL").Find(&devices).Error;err!=nil{return err}
  for _,device:=range devices{
   allowed,err:=acl.Allowed(tx,device.UserID,vaultID,acl.Read)
   if err!=nil{return err}
   if !allowed{continue}
   if err:=tx.Create(&models.RotationRecipient{RotationID:out.ID,DeviceID:device.ID,UserID:device.UserID}).Error;err!=nil{return err}
  }
  return nil
 })
 if err!=nil{
  if err==errRotationPending{problem(w,409,"rotation_pending");return}
  failure(w,err);return
 }
 write(w,201,map[string]any{"rotation_id":out.ID,"from_epoch":out.FromEpoch,"to_epoch":out.ToEpoch,"status":out.Status})
}

func(a *API) rotationStatus(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 var rotation models.VaultRotation
 if err:=a.db.Where("vault_id = ? AND status = ?",vaultID,"prepared").First(&rotation).Error;err!=nil{failure(w,err);return}
 var required int64
 if err:=a.db.Model(&models.RotationRecipient{}).Where("rotation_id = ?",rotation.ID).Count(&required).Error;err!=nil{failure(w,err);return}
 var staged int64
 if err:=a.db.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND key_epoch = ?",vaultID,rotation.ToEpoch).Count(&staged).Error;err!=nil{failure(w,err);return}
 write(w,200,map[string]any{"rotation_id":rotation.ID,"from_epoch":rotation.FromEpoch,"to_epoch":rotation.ToEpoch,"staged_envelopes":staged,"required_recipients":required,"status":rotation.Status,"can_activate":false,"reason":"atomic_activation_not_implemented"})
}

var errRotationPending = &rotationPendingError{}
type rotationPendingError struct{}
func(*rotationPendingError)Error()string{return "rotation already pending"}
