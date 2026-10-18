package api

import (
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type missingHistoricalEnvelope struct {
 DeviceID string `json:"device_id"`
 KeyEpoch uint64 `json:"key_epoch"`
}

type historicalCoverage struct {
 RequiredEpochs []uint64 `json:"required_historical_epochs"`
 Missing []missingHistoricalEnvelope `json:"missing_historical_envelopes"`
 Complete bool `json:"historical_envelopes_complete"`
}

// historicalEnvelopeCoverage checks metadata availability for every pinned
// recipient and every historical epoch represented by retained item revisions.
func historicalEnvelopeCoverage(tx *gorm.DB,rotation models.VaultRotation,recipients []models.RotationRecipient)(historicalCoverage,error){
 out:=historicalCoverage{RequiredEpochs:[]uint64{},Missing:[]missingHistoricalEnvelope{}}
 var epochs []uint64
 if err:=tx.Model(&models.ItemRevision{}).Distinct("key_epoch").
  Where("vault_id = ? AND key_epoch > 0 AND key_epoch < ?",rotation.VaultID,rotation.FromEpoch).
  Order("key_epoch").Pluck("key_epoch",&epochs).Error;err!=nil{return out,err}
 out.RequiredEpochs=epochs
 for _,recipient:=range recipients{
  for _,epoch:=range epochs{
   var count int64
   if err:=tx.Model(&models.DeviceKeyEnvelope{}).Where("vault_id = ? AND device_id = ? AND key_epoch = ?",rotation.VaultID,recipient.DeviceID,epoch).Count(&count).Error;err!=nil{return out,err}
   if count!=1{out.Missing=append(out.Missing,missingHistoricalEnvelope{DeviceID:recipient.DeviceID,KeyEpoch:epoch})}
  }
 }
 out.Complete=len(out.Missing)==0&&len(recipients)>0
 return out,nil
}
