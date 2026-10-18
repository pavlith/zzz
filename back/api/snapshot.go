package api

import (
 "net/http"
 "strconv"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// snapshot returns encrypted items as a bootstrap view.
// Snapshot pages are not pinned across requests: clients must pull changes afterwards.
func(a *API) snapshot(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 offset:=0
 if raw:=r.URL.Query().Get("offset");raw!=""{
  n,err:=strconv.Atoi(raw);if err!=nil||n<0||n>1000000{problem(w,400,"invalid_offset");return}
  offset=n
 }
 var vault models.Vault
 var eventsMax uint64
 var rows []models.Item
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  if err:=tx.Model(&models.SyncEvent{}).Where("vault_id = ?",vaultID).Select("COALESCE(MAX(id), 0)").Scan(&eventsMax).Error;err!=nil{return err}
  return tx.Where("vault_id = ?",vaultID).Order("id ASC").Offset(offset).Limit(101).Find(&rows).Error
 })
 if err!=nil{failure(w,err);return}
 more:=len(rows)>100
 if more{rows=rows[:100]}
 next:=offset+len(rows)
 write(w,http.StatusOK,map[string]any{
  "items":rows,"key_epoch":vault.KeyEpoch,
  "high_watermark":strconv.FormatUint(eventsMax,10),
  "next_offset":next,"has_more":more,
 })
}
