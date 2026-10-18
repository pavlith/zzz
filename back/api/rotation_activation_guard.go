package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/acl"
)

// activateRotation is a deliberately non-mutating safety gate.
// A signed acknowledgement is not cryptographic proof of key decryptability.
func(a *API) activateRotation(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 problem(w,http.StatusConflict,"rotation_activation_not_implemented")
}
