package api

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "net/http"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func historicalRewrapMessage(vaultID string,epoch uint64,source,target,hash string)[]byte {
 return []byte("zzz-historical-key-rewrap-v1:"+vaultID+":"+strconvFormatEpoch(epoch)+":"+source+":"+target+":"+hash)
}
func strconvFormatEpoch(epoch uint64)string{return strconv.FormatUint(epoch,10)}

// rewrapHistoricalEnvelope stores only opaque ciphertext generated client-side.
// A currently trusted managing source device must sign the exact submission.
func(a *API) rewrapHistoricalEnvelope(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 var input struct{
  SourceDeviceID string `json:"source_device_id"`
  DeviceID string `json:"device_id"`
  KeyEpoch uint64 `json:"key_epoch"`
  CryptoVersion uint32 `json:"crypto_version"`
  Ciphertext []byte `json:"ciphertext"`
  Signature []byte `json:"signature"`
 }
 if err:=decode(r,&input);err!=nil||input.SourceDeviceID==""||input.DeviceID==""||input.KeyEpoch==0||input.CryptoVersion!=1||len(input.Ciphertext)<32||len(input.Ciphertext)>65536||len(input.Signature)!=ed25519.SignatureSize{
  problem(w,400,"invalid_historical_rewrap");return
 }
 digest:=sha256.Sum256(input.Ciphertext)
 hash:=hex.EncodeToString(digest[:])
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  if input.KeyEpoch>=vault.KeyEpoch{return errKeyEpochMismatch}
  var source,target models.Device
  trusted:="verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL"
  if err:=tx.First(&source,"id = ? AND user_id = ? AND "+trusted,input.SourceDeviceID,userID).Error;err!=nil{return err}
  if err:=tx.First(&target,"id = ? AND "+trusted,input.DeviceID).Error;err!=nil{return err}
  canRead,err:=acl.Allowed(tx,target.UserID,vaultID,acl.Read)
  if err!=nil{return err}
  if !canRead{return gorm.ErrRecordNotFound}
  if !ed25519.Verify(ed25519.PublicKey(source.SigningPublicKey),historicalRewrapMessage(vaultID,input.KeyEpoch,input.SourceDeviceID,input.DeviceID,hash),input.Signature){return gorm.ErrRecordNotFound}
  var existing int64
  if err:=tx.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?",vaultID,input.SourceDeviceID,input.KeyEpoch).Count(&existing).Error;err!=nil{return err}
  if existing!=1{return gorm.ErrRecordNotFound}
  return tx.Create(&models.DeviceKeyEnvelope{ID:uuid.NewString(),VaultID:vaultID,DeviceID:input.DeviceID,KeyEpoch:input.KeyEpoch,CryptoVersion:input.CryptoVersion,Ciphertext:input.Ciphertext}).Error
 })
 if err!=nil{
  if err==errKeyEpochMismatch{problem(w,409,"historical_epoch_required");return}
  problem(w,409,"historical_rewrap_conflict");return
 }
 write(w,http.StatusCreated,map[string]bool{"stored":true})
}
