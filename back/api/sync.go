package api

import (
 "net/http"
 "strconv"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
)

// pullSync returns journal metadata only. Clients fetch encrypted items separately.
func (a *API) pullSync(w http.ResponseWriter,r *http.Request,userID string) {
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Read){return}
 var cursor uint64
 if v:=r.URL.Query().Get("cursor");v!="" {
  n,err:=strconv.ParseUint(v,10,64)
  if err!=nil{problem(w,400,"invalid_cursor");return}
  cursor=n
 }
 var events []models.SyncEvent
 if err:=a.db.Where("vault_id = ? AND id > ?",vaultID,cursor).Order("id ASC").Limit(101).Find(&events).Error;err!=nil{failure(w,err);return}
 hasMore:=len(events)>100
 if hasMore{events=events[:100]}
 next:=cursor
 if len(events)>0{next=events[len(events)-1].ID}
 write(w,http.StatusOK,map[string]any{
  "events":events,
  "next_cursor":strconv.FormatUint(next,10),
  "has_more":hasMore,
 })
}
