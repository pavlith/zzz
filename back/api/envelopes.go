package api

import (
 "net/http"
 "encoding/json"

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
  Where("device_key_envelopes.vault_id = ? AND devices.user_id = ? AND devices.revoked_at IS NULL AND devices.verified_at IS NOT NULL AND devices.trusted_at IS NOT NULL AND device_key_envelopes.key_epoch = vaults.key_epoch",vaultID,userID).
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
  Envelope json.RawMessage `json:"envelope"`
 }
 if err:=decode(r,&in);err!=nil || in.DeviceID=="" || len(in.Envelope)==0 || len(in.Envelope)>65536 {
  problem(w,400,"invalid_envelope");return
 }
 var vault models.Vault
 if err:=a.db.First(&vault,"id = ?",vaultID).Error;err!=nil {failure(w,err);return}
 if vault.KeyEpoch!=in.KeyEpoch {
  var rotations int64
  if err:=a.db.Model(&models.VaultRotation{}).Where("vault_id = ? AND from_epoch = ? AND to_epoch = ? AND status = ?",vaultID,vault.KeyEpoch,in.KeyEpoch,"prepared").Count(&rotations).Error;err!=nil{failure(w,err);return}
  if rotations!=1 {problem(w,409,"key_epoch_mismatch");return}
  var rotation models.VaultRotation
  if err:=a.db.Where("vault_id = ? AND from_epoch = ? AND to_epoch = ? AND status = ?",vaultID,vault.KeyEpoch,in.KeyEpoch,"prepared").First(&rotation).Error;err!=nil{failure(w,err);return}
  var member int64
  if err:=a.db.Model(&models.RotationRecipient{}).Where("rotation_id = ? AND device_id = ?",rotation.ID,in.DeviceID).Count(&member).Error;err!=nil{failure(w,err);return}
  if member!=1{problem(w,409,"recipient_not_in_rotation");return}
 }
 var device models.Device
 if err:=a.db.First(&device,"id = ? AND revoked_at IS NULL AND verified_at IS NOT NULL AND trusted_at IS NOT NULL",in.DeviceID).Error;err!=nil {failure(w,err);return}
 permitted,err:=acl.Allowed(a.db,device.UserID,vaultID,acl.Read)
 if err!=nil || !permitted {problem(w,404,"recipient_not_allowed");return}
 ciphertext,err:=decodeCandidateEnvelopeRequest(in.Envelope,vaultID,in.DeviceID,in.KeyEpoch)
 if err!=nil{problem(w,400,"invalid_envelope");return}
 item:=models.DeviceKeyEnvelope{
  ID:uuid.NewString(),VaultID:vaultID,DeviceID:device.ID,
  KeyEpoch:in.KeyEpoch,CryptoVersion:1,Ciphertext:ciphertext,
 }
 if err:=a.db.Create(&item).Error;err!=nil {failure(w,err);return}
 write(w,http.StatusCreated,item)
}
