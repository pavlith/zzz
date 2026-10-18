package api

import (
 "crypto/ed25519"
 "encoding/hex"
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func rotationSignMessage(rotation models.VaultRotation)[]byte{
 return []byte("zzz-vault-rotation-approval-v1:"+rotation.VaultID+":"+rotation.ID+":"+rotation.ManifestSHA256)
}

func(a *API) signRotation(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 var input struct{DeviceID string `json:"device_id"`;ManifestSHA256 string `json:"manifest_sha256"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&input);err!=nil||input.DeviceID==""||len(input.Signature)!=ed25519.SignatureSize||len(input.ManifestSHA256)!=64{
  problem(w,400,"invalid_rotation_approval");return
 }
 if _,err:=hex.DecodeString(input.ManifestSHA256);err!=nil{problem(w,400,"invalid_manifest_digest");return}
 var rotation models.VaultRotation
 if err:=a.db.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{failure(w,err);return}
 if input.ManifestSHA256!=rotation.ManifestSHA256{problem(w,409,"manifest_mismatch");return}
 validation,err:=validateRotation(a.db,rotation)
 if err!=nil{failure(w,err);return}
 if !validation.ManifestValid{problem(w,409,"manifest_invalid");return}
 var signer models.Device
 if err:=a.db.First(&signer,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",input.DeviceID,userID).Error;err!=nil{problem(w,403,"device_not_trusted");return}
 if !ed25519.Verify(ed25519.PublicKey(signer.SigningPublicKey),rotationSignMessage(rotation),input.Signature){problem(w,400,"invalid_signature");return}
 err=a.db.Transaction(func(tx *gorm.DB)error{
  var current models.VaultRotation
  if err:=tx.First(&current,"id = ? AND status = ? AND manifest_sha256 = ?",rotation.ID,"prepared",input.ManifestSHA256).Error;err!=nil{return err}
  var active models.Device
  if err:=tx.First(&active,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",input.DeviceID,userID).Error;err!=nil{return err}
  if !ed25519.Verify(ed25519.PublicKey(active.SigningPublicKey),rotationSignMessage(current),input.Signature){return gorm.ErrRecordNotFound}
  var recipients []models.RotationRecipient
  if err:=tx.Where("rotation_id = ?",current.ID).Order("device_id").Find(&recipients).Error;err!=nil{return err}
  if manifestDigest(current,recipients)!=current.ManifestSHA256{return gorm.ErrRecordNotFound}
  return tx.Create(&models.RotationSignature{RotationID:current.ID,DeviceID:active.ID,ManifestSHA256:current.ManifestSHA256,Signature:input.Signature}).Error
 })
 if err!=nil{problem(w,409,"rotation_approval_conflict");return}
 write(w,201,map[string]bool{"approved":true})
}
