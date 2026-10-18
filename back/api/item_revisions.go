package api

import (
 "net/http"
 "strconv"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
)

func (a *API) itemRevisions(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID,itemID:=r.PathValue("vault"),r.PathValue("item")
 if !a.check(w,userID,vaultID,acl.Read){return}
 after:=uint64(0)
 if raw:=r.URL.Query().Get("after");raw!=""{
  value,err:=strconv.ParseUint(raw,10,64)
  if err!=nil{problem(w,400,"invalid_revision");return}
  after=value
 }
 var records []models.ItemRevision
 err:=a.db.Where("vault_id = ? AND item_id = ? AND revision > ?",vaultID,itemID,after).
  Order("revision ASC").Limit(101).Find(&records).Error
 if err!=nil{failure(w,err);return}
 more:=len(records)>100
 if more{records=records[:100]}
 next:=after
 if len(records)>0{next=records[len(records)-1].Revision}
 write(w,http.StatusOK,map[string]any{
  "revisions":records,"next_revision":strconv.FormatUint(next,10),"has_more":more,
 })
}
