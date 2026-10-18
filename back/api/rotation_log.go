package api

import (
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "errors"
 "hash"

 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

var errRotationLogCorrupt=errors.New("rotation commitment chain corrupted")

func logField(h hash.Hash,b []byte){var n [8]byte;binary.BigEndian.PutUint64(n[:],uint64(len(b)));_,_=h.Write(n[:]);_,_=h.Write(b)}
func rotationLogHash(row models.RotationLogEntry)string{
 h:=sha256.New()
 for _,s:=range []string{"zzz-rotation-log-v1",row.RotationID,row.DeviceID,row.ManifestSHA256,row.KeyCommitment,row.PrevHash}{logField(h,[]byte(s))}
 logField(h,row.Signature)
 return hex.EncodeToString(h.Sum(nil))
}
func rotationLogRead(tx *gorm.DB,id string)([]models.RotationLogEntry,error){
 var entries []models.RotationLogEntry
 if err:=tx.Where("rotation_id = ?",id).Order("id").Find(&entries).Error;err!=nil{return nil,err}
 prev:=""
 for _,entry:=range entries{
  if entry.PrevHash!=prev||entry.EntryHash!=rotationLogHash(entry){return nil,errRotationLogCorrupt}
  prev=entry.EntryHash
 }
 return entries,nil
}
func appendRotationCommitment(tx *gorm.DB,claim models.RotationCommitment)error{
 entries,err:=rotationLogRead(tx,claim.RotationID);if err!=nil{return err}
 prev:=""
 if len(entries)>0{prev=entries[len(entries)-1].EntryHash}
 entry:=models.RotationLogEntry{RotationID:claim.RotationID,DeviceID:claim.DeviceID,ManifestSHA256:claim.ManifestSHA256,KeyCommitment:claim.KeyCommitment,Signature:claim.Signature,PrevHash:prev}
 entry.EntryHash=rotationLogHash(entry)
 return tx.Create(&entry).Error
}
