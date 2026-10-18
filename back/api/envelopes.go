package api

import (
 "net/http"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
)

func (a *API) listKeyEnvelopes(w http.ResponseWriter, r *http.Request, userID string) {
 vaultID := r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read) { return }
 var records []models.DeviceKeyEnvelope
 err := a.db.Model(&models.DeviceKeyEnvelope{}).
  Joins("JOIN devices ON devices.id = device_key_envelopes.device_id").
  Joins("JOIN vaults ON vaults.id = device_key_envelopes.vault_id").
  Where("device_key_envelopes.vault_id = ? AND devices.user_id = ? AND devices.revoked_at IS NULL AND device_key_envelopes.key_epoch = vaults.key_epoch",vaultID,userID).
  Find(&records).Error
 if err != nil { failure(w,err);return }
 write(w,http.StatusOK,records)
}

func (a *API) createKeyEnvelope(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID := r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage) {return}
 var in struct {
  DeviceID string `json:"device_id"`
  KeyEpoch uint64 `json:"key_epoch"`
  CryptoVersion uint32 `json:"crypto_version"`
  Ciphertext []byte `json:"ciphertext"`
 }
 if err:=decode(r,&in);err!=nil || in.DeviceID=="" || in.CryptoVersion!=1 || len(in.Ciphertext)<32 || len(in.Ciphertext)>65536 {
  problem(w,400,"invalid_envelope");return
 }
 var vault models.Vault
 if err:=a.db.First(&vault,"id = ?",vaultID).Error;err!=nil {failure(w,err);return}
 if vault.KeyEpoch!=in.KeyEpoch {problem(w,409,"key_epoch_mismatch");return}
 var device models.Device
 if err:=a.db.First(&device,"id = ? AND revoked_at IS NULL",in.DeviceID).Error;err!=nil {failure(w,err);return}
 permitted,err:=acl.Allowed(a.db,device.UserID,vaultID,acl.Read)
 if err!=nil || !permitted {problem(w,404,"recipient_not_allowed");return}
 item:=models.DeviceKeyEnvelope{
  ID:uuid.NewString(),VaultID:vaultID,DeviceID:device.ID,
  KeyEpoch:in.KeyEpoch,CryptoVersion:in.CryptoVersion,Ciphertext:in.Ciphertext,
 }
 if err:=a.db.Create(&item).Error;err!=nil {failure(w,err);return}
 write(w,http.StatusCreated,item)
}
