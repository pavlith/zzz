package api

import (
 "net/http"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type rotationPreflight struct {
 RotationID string `json:"rotation_id"`
 ManifestValid bool `json:"manifest_valid"`
 EnvelopesComplete bool `json:"envelopes_complete"`
 RequiredApprovals uint32 `json:"required_approvals"`
 ValidApprovals int `json:"valid_approvals"`
 QuorumMet bool `json:"quorum_met"`
 Blockers []string `json:"blockers"`
 CanActivate bool `json:"can_activate"`
}

// activationPreflight checks a consistent database snapshot. It deliberately
// makes no state changes and cannot prove client-side envelope decryptability.
func activationPreflight(db *gorm.DB,vaultID string)(rotationPreflight,error){
 out:=rotationPreflight{Blockers:[]string{},CanActivate:false}
 err:=db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  out.RotationID=rotation.ID
  recipient,err:=validateRotation(tx,rotation)
  if err!=nil{return err}
  signatures,err:=validateRotationSignatures(tx,rotation)
  if err!=nil{return err}
  out.ManifestValid=recipient.ManifestValid
  out.EnvelopesComplete=recipient.Complete
  out.RequiredApprovals=rotation.RequiredApprovals
  out.ValidApprovals=signatures.Valid
  out.QuorumMet=rotation.RequiredApprovals>0&&signatures.Valid>=int(rotation.RequiredApprovals)
  if !recipient.ManifestValid{out.Blockers=append(out.Blockers,"manifest_invalid")}
  if !recipient.EpochCurrent{out.Blockers=append(out.Blockers,"epoch_changed")}
  if recipient.Required==0{out.Blockers=append(out.Blockers,"empty_manifest")}
  if len(recipient.Missing)>0{out.Blockers=append(out.Blockers,"envelopes_missing")}
  if len(recipient.Invalid)>0{out.Blockers=append(out.Blockers,"recipients_invalid")}
  if len(recipient.Unlisted)>0{out.Blockers=append(out.Blockers,"recipients_unlisted")}
  if !out.QuorumMet{out.Blockers=append(out.Blockers,"quorum_not_met")}
  // The key cryptographic proof and historical-key retention policies remain missing.
  out.Blockers=append(out.Blockers,"envelope_decryptability_unverified","historical_key_access_unverified")
  return nil
 })
 return out,err
}
func(a *API) rotationPreflightEndpoint(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 result,err:=activationPreflight(a.db,vaultID)
 if err!=nil{failure(w,err);return}
 write(w,http.StatusOK,result)
}
