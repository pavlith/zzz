package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/models"
)

func(a *API) deviceAudit(w http.ResponseWriter,r *http.Request,userID string){
 var rows []models.DeviceAudit
 if err:=a.db.Where("user_id = ?",userID).Order("id DESC").Limit(100).Find(&rows).Error;err!=nil{failure(w,err);return}
 write(w,http.StatusOK,rows)
}
