package api

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"

 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func historicalAckCoverage(tx *gorm.DB,rotation models.VaultRotation,recipients []models.RotationRecipient,epochs []uint64)(int,error){
 valid:=0
 for _,recipient:=range recipients{
  var device models.Device
  err:=tx.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",recipient.DeviceID,recipient.UserID).Error
  if err!=nil{
   if err==gorm.ErrRecordNotFound{continue}
   return 0,err
  }
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=recipient.SigningKeySHA256||hex.EncodeToString(encryption[:])!=recipient.EncryptionKeySHA256{continue}
  for _,epoch:=range epochs{
   var ack models.RotationHistoryAck
   if err:=tx.First(&ack,"rotation_id = ? AND device_id = ? AND key_epoch = ?",rotation.ID,device.ID,epoch).Error;err!=nil{
    if err==gorm.ErrRecordNotFound{continue}
    return 0,err
   }
   var envelope models.DeviceKeyEnvelope
   if err:=tx.First(&envelope,"vault_id = ? AND device_id = ? AND key_epoch = ?",rotation.VaultID,device.ID,epoch).Error;err!=nil{
    if err==gorm.ErrRecordNotFound{continue}
    return 0,err
   }
   digest:=sha256.Sum256(envelope.Envelope)
   if hex.EncodeToString(digest[:])!=ack.EnvelopeSHA256{continue}
   if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),historicalAckMessage(rotation,device.ID,epoch,ack.EnvelopeSHA256),ack.Signature){continue}
   valid++
  }
 }
 return valid,nil
}
