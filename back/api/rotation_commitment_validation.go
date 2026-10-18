package api

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type commitmentComparison struct {
 Required int `json:"required_key_commitments"`
 Valid int `json:"valid_key_commitments"`
 Distinct int `json:"distinct_key_commitments"`
 Conflicting bool `json:"key_commitment_conflict"`
 Consensus bool `json:"key_commitment_consensus"`
}

func compareRotationCommitments(tx *gorm.DB,rotation models.VaultRotation,recipients []models.RotationRecipient)(commitmentComparison,error){
 out:=commitmentComparison{Required:len(recipients)}
 hashes:=map[string]bool{}
 for _,recipient:=range recipients{
  var claim models.RotationCommitment
  if err:=tx.First(&claim,"rotation_id = ? AND device_id = ?",rotation.ID,recipient.DeviceID).Error;err!=nil{
   if err==gorm.ErrRecordNotFound{continue}
   return out,err
  }
  if claim.ManifestSHA256!=rotation.ManifestSHA256{continue}
  var device models.Device
  if err:=tx.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",recipient.DeviceID,recipient.UserID).Error;err!=nil{
   if err==gorm.ErrRecordNotFound{continue}
   return out,err
  }
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=recipient.SigningKeySHA256||hex.EncodeToString(encryption[:])!=recipient.EncryptionKeySHA256{continue}
  permitted,err:=acl.Allowed(tx,device.UserID,rotation.VaultID,acl.Read)
  if err!=nil{return out,err}
  if !permitted||!ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),rotationCommitmentMessage(rotation,device.ID,claim.KeyCommitment),claim.Signature){continue}
  out.Valid++
  hashes[claim.KeyCommitment]=true
 }
 out.Distinct=len(hashes)
 out.Conflicting=out.Distinct>1
 out.Consensus=out.Required>0&&out.Valid==out.Required&&out.Distinct==1
 return out,nil
}
