package api

import (
 "net/http"
 "strconv"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
)

// historicalKeyEnvelopes returns only already-issued envelopes for the
// authenticated account's active trusted devices; future epochs are excluded.
func(a *API) historicalKeyEnvelopes(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 epoch,err:=strconv.ParseUint(r.URL.Query().Get("epoch"),10,64)
 if err!=nil||epoch==0{problem(w,400,"invalid_key_epoch");return}
 var vault models.Vault
 if err:=a.db.First(&vault,"id = ?",vaultID).Error;err!=nil{failure(w,err);return}
 if epoch>=vault.KeyEpoch{problem(w,400,"historical_epoch_required");return}
 var rows []models.DeviceKeyEnvelope
 err=a.db.Model(&models.DeviceKeyEnvelope{}).
  Joins("JOIN devices ON devices.id = device_key_envelopes.device_id").
  Where("device_key_envelopes.vault_id = ? AND device_key_envelopes.key_epoch = ? AND devices.user_id = ? AND devices.verified_at IS NOT NULL AND devices.trusted_at IS NOT NULL AND devices.revoked_at IS NULL",vaultID,epoch,userID).
  Order("device_key_envelopes.device_id").Find(&rows).Error
 if err!=nil{failure(w,err);return}
 responses,err:=envelopeResponses(rows)
 if err!=nil{problem(w,500,"invalid_stored_envelope");return}
 write(w,200,responses)
}
