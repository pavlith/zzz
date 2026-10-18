package api

import (
 "net/http"
 "time"

 "github.com/pavlith/zzz/back/auth"
)

func(a *API) listSessions(w http.ResponseWriter,r *http.Request,userID string){
 type session struct {
  ID string `json:"id"`
  DeviceID *string `json:"device_id,omitempty"`
  CreatedAt time.Time `json:"created_at"`
  ExpiresAt time.Time `json:"expires_at"`
  RevokedAt *time.Time `json:"revoked_at,omitempty"`
 }
 var rows []session
 err:=a.db.Model(&auth.Token{}).Select("id, device_id, created_at, expires_at, revoked_at").
  Where("user_id = ?",userID).Order("created_at DESC").Limit(100).Scan(&rows).Error
 if err!=nil{failure(w,err);return}
 write(w,200,rows)
}

func(a *API) revokeSession(w http.ResponseWriter,r *http.Request,userID string){
 now:=time.Now().UTC()
 result:=a.db.Model(&auth.Token{}).Where("id = ? AND user_id = ? AND revoked_at IS NULL",r.PathValue("session"),userID).Update("revoked_at",now)
 if result.Error!=nil{failure(w,result.Error);return}
 if result.RowsAffected!=1{problem(w,404,"not_found");return}
 write(w,200,map[string]bool{"revoked":true})
}
