package api

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "net/http"
 "time"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

// These unauthenticated endpoints require possession of a trusted device private key.
func(a *API) sessionChallenge(w http.ResponseWriter,r *http.Request){
 var in struct{DeviceID string `json:"device_id"`}
 if err:=decode(r,&in);err!=nil||in.DeviceID==""{problem(w,400,"invalid_device");return}
 var device models.Device
 if err:=a.db.First(&device,"id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",in.DeviceID).Error;err!=nil{problem(w,404,"device_not_found");return}
 nonce:=make([]byte,32)
 if _,err:=rand.Read(nonce);err!=nil{problem(w,500,"random_failed");return}
 challenge:=models.DeviceSessionChallenge{ID:uuid.NewString(),DeviceID:device.ID,Nonce:nonce,ExpiresAt:time.Now().UTC().Add(5*time.Minute)}
 if err:=a.db.Create(&challenge).Error;err!=nil{failure(w,err);return}
 write(w,201,map[string]string{"challenge_id":challenge.ID,"nonce":base64.StdEncoding.EncodeToString(nonce)})
}

func(a *API) createDeviceSession(w http.ResponseWriter,r *http.Request){
 var in struct{DeviceID string `json:"device_id"`;ChallengeID string `json:"challenge_id"`;Signature []byte `json:"signature"`}
 if err:=decode(r,&in);err!=nil||in.DeviceID==""||in.ChallengeID==""||len(in.Signature)!=ed25519.SignatureSize{problem(w,400,"invalid_session_proof");return}
 now:=time.Now().UTC()
 var challenge models.DeviceSessionChallenge
 if err:=a.db.First(&challenge,"id = ? AND device_id = ? AND used_at IS NULL AND expires_at > ?",in.ChallengeID,in.DeviceID,now).Error;err!=nil{problem(w,400,"invalid_challenge");return}
 var device models.Device
 if err:=a.db.First(&device,"id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",in.DeviceID).Error;err!=nil{problem(w,403,"untrusted_device");return}
 signed:=append([]byte("zzz-device-session-v1:"+device.UserID+":"+device.ID+":"+challenge.ID+":"),challenge.Nonce...)
 if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),signed,in.Signature){problem(w,400,"invalid_signature");return}
 var token string
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  claim:=tx.Model(&models.DeviceSessionChallenge{}).Where("id = ? AND device_id = ? AND used_at IS NULL AND expires_at > ?",challenge.ID,device.ID,now).Update("used_at",now)
  if claim.Error!=nil{return claim.Error}
  if claim.RowsAffected!=1{return gorm.ErrRecordNotFound}
  var current models.Device
  if err:=tx.First(&current,"id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",device.ID).Error;err!=nil{return err}
  issued,err:=auth.IssueForDevice(tx,current.UserID,current.ID,time.Hour)
  if err!=nil{return err}
  token=issued
  return nil
 })
 if err!=nil{problem(w,409,"session_conflict");return}
 write(w,201,map[string]any{"token":token,"token_type":"Bearer","expires_in":3600,"device_id":device.ID})
}
