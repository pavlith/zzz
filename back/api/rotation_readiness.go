package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
)

// rotationReadiness reports eligible recipients. It never changes key epochs.
func (a *API) rotationReadiness(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 var vault models.Vault
 if err:=a.db.First(&vault,"id = ?",vaultID).Error;err!=nil{failure(w,err);return}
 type recipient struct {
  DeviceID string `json:"device_id"`
  UserID string `json:"user_id"`
 }
 var candidates []recipient
 err:=a.db.Model(&models.Device{}).
  Select("devices.id AS device_id, devices.user_id AS user_id").
  Joins("JOIN workspace_members wm ON wm.user_id = devices.user_id AND wm.workspace_id = ?",vault.WorkspaceID).
  Where("devices.verified_at IS NOT NULL AND devices.revoked_at IS NULL").
  Order("devices.id").Scan(&candidates).Error
 if err!=nil{failure(w,err);return}
 eligible:=make([]recipient,0,len(candidates))
 for _,candidate:=range candidates{
  allowed,err:=acl.Allowed(a.db,candidate.UserID,vaultID,acl.Read)
  if err!=nil{failure(w,err);return}
  if allowed{eligible=append(eligible,candidate)}
 }
 write(w,http.StatusOK,map[string]any{
  "vault_id":vaultID,
  "current_key_epoch":vault.KeyEpoch,
  "proposed_key_epoch":vault.KeyEpoch+1,
  "eligible_devices":eligible,
  "eligible_device_count":len(eligible),
  "can_activate":false,
  "reason":"trusted_device_approval_not_implemented",
 })
}
