package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

func(a *API) rotationTransparencyLog(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 var out struct {
  RotationID string `json:"rotation_id"`
  Entries []models.RotationLogEntry `json:"entries"`
  Head string `json:"head_sha256"`
  Size int `json:"size"`
 }
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  out.RotationID=rotation.ID
  entries,err:=rotationLogRead(tx,rotation.ID);if err!=nil{return err}
  out.Entries=entries;out.Size=len(entries)
  if len(entries)>0{out.Head=entries[len(entries)-1].EntryHash}
  return nil
 })
 if err!=nil{failure(w,err);return}
 write(w,http.StatusOK,out)
}
