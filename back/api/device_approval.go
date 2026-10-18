package api

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "net/http"
 "time"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// approvalChallenge issues a short-lived challenge for an already trusted approver.
func(a *API) approvalChallenge(w http.ResponseWriter,r *http.Request,userID string) {
 var in struct{ApproverDeviceID string `json:"approver_device_id"`}
 if err:=decode(r,&in);err!=nil||in.ApproverDeviceID==""{problem(w,400,"invalid_approver");return}
 var target,approver models.Device
 if err:=a.db.First(&target,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NULL AND revoked_at IS NULL",r.PathValue("device"),userID).Error;err!=nil{failure(w,err);return}
 if err:=a.db.First(&approver,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",in.ApproverDeviceID,userID).Error;err!=nil{problem(w,404,"trusted_approver_not_found");return}
 nonce:=make([]byte,32)
 if _,err:=rand.Read(nonce);err!=nil{problem(w,500,"random_failed");return}
 challenge:=models.DeviceApprovalChallenge{ID:uuid.NewString(),UserID:userID,TargetDeviceID:target.ID,ApproverDeviceID:approver.ID,Nonce:nonce,ExpiresAt:time.Now().UTC().Add(5*time.Minute)}
 if err:=a.db.Create(&challenge).Error;err!=nil{failure(w,err);return}
 write(w,201,map[string]string{"challenge_id":challenge.ID,"nonce":base64.StdEncoding.EncodeToString(nonce)})
}

func(a *API) approveDevice(w http.ResponseWriter,r *http.Request,userID string) {
 var in struct{ChallengeID string `json:"challenge_id"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&in);err!=nil||in.ChallengeID==""||len(in.Signature)!=ed25519.SignatureSize{problem(w,400,"invalid_approval");return}
 now:=time.Now().UTC()
 var challenge models.DeviceApprovalChallenge
 if err:=a.db.First(&challenge,"id = ? AND user_id = ? AND target_device_id = ? AND used_at IS NULL AND expires_at > ?",in.ChallengeID,userID,r.PathValue("device"),now).Error;err!=nil{problem(w,400,"invalid_challenge");return}
 var target,approver models.Device
 if err:=a.db.First(&target,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NULL AND revoked_at IS NULL",challenge.TargetDeviceID,userID).Error;err!=nil{failure(w,err);return}
 if err:=a.db.First(&approver,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",challenge.ApproverDeviceID,userID).Error;err!=nil{problem(w,403,"approver_not_trusted");return}
 message:=append([]byte("zzz-device-approval-v1:"+userID+":"+target.ID+":"+approver.ID+":"+challenge.ID+":"),target.SigningPublicKey...)
 message=append(message,target.EncryptionPublicKey...)
 message=append(message,challenge.Nonce...)
 if !ed25519.Verify(ed25519.PublicKey(approver.SigningPublicKey),message,in.Signature){problem(w,400,"invalid_signature");return}
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  result:=tx.Model(&models.DeviceApprovalChallenge{}).Where("id = ? AND used_at IS NULL AND expires_at > ?",challenge.ID,now).Update("used_at",now)
  if result.Error!=nil{return result.Error}
  if result.RowsAffected!=1{return gorm.ErrRecordNotFound}
  var current models.Device
  if err:=tx.First(&current,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",approver.ID,userID).Error;err!=nil{return err}
  result=tx.Model(&models.Device{}).Where("id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NULL AND revoked_at IS NULL",target.ID,userID).Update("trusted_at",now)
  if result.Error!=nil{return result.Error}
  if result.RowsAffected!=1{return gorm.ErrRecordNotFound}
  return nil
 })
 if err!=nil{problem(w,409,"approval_conflict");return}
 write(w,200,map[string]bool{"trusted":true})
}
