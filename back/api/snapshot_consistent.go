package api

import (
 "net/http"
 "strconv"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// consistentSnapshot uses immutable encrypted revisions at a fixed event watermark.
// Pages are ordered by item ID, which remains stable as new events arrive.
func (a *API) consistentSnapshot(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 after:=r.URL.Query().Get("after")
 if len(after)>128{problem(w,400,"invalid_after");return}
 var watermark uint64
 if raw:=r.URL.Query().Get("watermark");raw!="" {
  n,err:=strconv.ParseUint(raw,10,64)
  if err!=nil{problem(w,400,"invalid_watermark");return}
  watermark=n
 }
 var records []models.ItemRevision
 var vault models.Vault
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  if r.URL.Query().Get("watermark")==""{
   if err:=tx.Model(&models.SyncEvent{}).Where("vault_id = ?",vaultID).
    Select("COALESCE(MAX(id), 0)").Scan(&watermark).Error;err!=nil{return err}
  }
  // Select the latest event for each item at or before the fixed watermark.
  // Join the corresponding immutable encrypted revision rather than current Items.
  return tx.Raw(`
SELECT revisions.*
FROM item_revisions AS revisions
JOIN (
 SELECT item_id, MAX(id) AS latest_event_id
 FROM sync_events
 WHERE vault_id = ? AND id <= ? AND item_id > ?
 GROUP BY item_id
) AS latest ON latest.item_id = revisions.item_id
JOIN sync_events AS event ON event.id = latest.latest_event_id
WHERE revisions.vault_id = ? AND revisions.revision = event.revision
ORDER BY revisions.item_id ASC
LIMIT 101`,vaultID,watermark,after,vaultID).Scan(&records).Error
 })
 if err!=nil{failure(w,err);return}
 more:=len(records)>100
 if more{records=records[:100]}
 next:=after
 if len(records)>0{next=records[len(records)-1].ItemID}
 write(w,http.StatusOK,map[string]any{
  "revisions":records,"watermark":strconv.FormatUint(watermark,10),
  "next_after":next,"has_more":more,"key_epoch":vault.KeyEpoch,
 })
}
