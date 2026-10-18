package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func(a *API) cancelRotation(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  if vault.KeyEpoch!=rotation.FromEpoch{return errKeyEpochMismatch}
  changed:=tx.Model(&models.VaultRotation{}).Where("id = ? AND status = ?",""+rotation.ID,"prepared").Update("status","cancelled")
  if changed.Error!=nil{return changed.Error}
  if changed.RowsAffected!=1{return gorm.ErrRecordNotFound}
  if err:=tx.Where("vault_id = ? AND key_epoch = ?",vaultID,rotation.ToEpoch).Delete(&models.DeviceKeyEnvelope{}).Error;err!=nil{return err}
  return nil
 })
 if err!=nil{
  if err==errKeyEpochMismatch{problem(w,409,"key_epoch_mismatch");return}
  failure(w,err);return
 }
 write(w,http.StatusOK,map[string]bool{"cancelled":true})
}
