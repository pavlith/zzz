package api

import (
 "crypto/sha256"
 "encoding/hex"
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type commitmentWitness struct {
 DeviceID string `json:"device_id"`
 KeyCommitment string `json:"key_commitment"`
 ManifestSHA256 string `json:"manifest_sha256"`
 Signature []byte `json:"signature"`
}
type commitmentView struct {
 RotationID string `json:"rotation_id"`
 ManifestSHA256 string `json:"manifest_sha256"`
 Entries []commitmentWitness `json:"entries"`
 ViewSHA256 string `json:"view_sha256"`
}

func rotationCommitmentView(tx *gorm.DB,rotation models.VaultRotation)(commitmentView,error){
 out:=commitmentView{RotationID:rotation.ID,ManifestSHA256:rotation.ManifestSHA256,Entries:[]commitmentWitness{}}
 var rows []models.RotationCommitment
 if err:=tx.Where("rotation_id = ?",rotation.ID).Order("device_id").Find(&rows).Error;err!=nil{return out,err}
 h:=sha256.New()
 field(h,[]byte("zzz-rotation-commitment-view-v1"))
 field(h,[]byte(rotation.VaultID))
 field(h,[]byte(rotation.ID))
 field(h,[]byte(rotation.ManifestSHA256))
 for _,row:=range rows{
  field(h,[]byte(row.DeviceID))
  field(h,[]byte(row.ManifestSHA256))
  field(h,[]byte(row.KeyCommitment))
  field(h,row.Signature)
  out.Entries=append(out.Entries,commitmentWitness{DeviceID:row.DeviceID,KeyCommitment:row.KeyCommitment,ManifestSHA256:row.ManifestSHA256,Signature:row.Signature})
 }
 out.ViewSHA256=hex.EncodeToString(h.Sum(nil))
 return out,nil
}

func(a *API) rotationCommitmentViewEndpoint(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 var result commitmentView
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  var err error
  result,err=rotationCommitmentView(tx,rotation)
  return err
 })
 if err!=nil{failure(w,err);return}
 write(w,200,result)
}
