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

func (a *API) issueDeviceChallenge(w http.ResponseWriter, r *http.Request, userID string) {
 var device models.Device
 if err := a.db.First(&device, "id = ? AND user_id = ? AND revoked_at IS NULL", r.PathValue("device"), userID).Error; err != nil { failure(w,err);return }
 if device.VerifiedAt != nil {problem(w,409,"already_verified");return}
 nonce:=make([]byte,32)
 if _,err:=rand.Read(nonce);err!=nil{problem(w,500,"random_failed");return}
 challenge:=models.DeviceChallenge{ID:uuid.NewString(),DeviceID:device.ID,Nonce:nonce,ExpiresAt:time.Now().UTC().Add(5*time.Minute)}
 if err:=a.db.Create(&challenge).Error;err!=nil{failure(w,err);return}
 write(w,201,map[string]string{"challenge_id":challenge.ID,"nonce":base64.StdEncoding.EncodeToString(nonce)})
}

func (a *API) verifyDevice(w http.ResponseWriter,r *http.Request,userID string) {
 var input struct {ChallengeID string `json:"challenge_id"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&input);err!=nil||input.ChallengeID==""||len(input.Signature)!=64{problem(w,400,"invalid_proof");return}
 var device models.Device
 if err:=a.db.First(&device,"id = ? AND user_id = ? AND revoked_at IS NULL",r.PathValue("device"),userID).Error;err!=nil{failure(w,err);return}
 if device.VerifiedAt!=nil{problem(w,409,"already_verified");return}
 now:=time.Now().UTC()
 var challenge models.DeviceChallenge
 if err:=a.db.First(&challenge,"id = ? AND device_id = ? AND used_at IS NULL AND expires_at > ?",input.ChallengeID,device.ID,now).Error;err!=nil{problem(w,400,"invalid_challenge");return}
 message:=append([]byte("zzz-device-proof-v1:"+userID+":"+device.ID+":"+challenge.ID+":"),challenge.Nonce...)
 if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),message,input.Signature){problem(w,400,"invalid_signature");return}
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  update:=tx.Model(&models.DeviceChallenge{}).Where("id = ? AND used_at IS NULL AND expires_at > ?",challenge.ID,now).Update("used_at",now)
  if update.Error!=nil{return update.Error}
  if update.RowsAffected!=1{return gorm.ErrRecordNotFound}
  update=tx.Model(&models.Device{}).Where("id = ? AND user_id = ? AND verified_at IS NULL AND revoked_at IS NULL",device.ID,userID).Update("verified_at",now)
  if update.Error!=nil{return update.Error}
  if update.RowsAffected!=1{return gorm.ErrRecordNotFound}
  return nil
 })
 if err!=nil{problem(w,409,"challenge_consumed");return}
 write(w,200,map[string]bool{"verified":true})
}
