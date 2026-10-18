package auth

import (
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "errors"
 "strings"
 "time"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type Token struct {
 ID string `gorm:"primaryKey;size:36"`
 UserID string `gorm:"index;not null"`
 DeviceID *string `gorm:"index"`
 Hash string `gorm:"uniqueIndex;size:64;not null"`
 CreatedAt time.Time
 ExpiresAt time.Time
 RevokedAt *time.Time
}
func Hash(raw string)string{ sum:=sha256.Sum256([]byte(raw));return hex.EncodeToString(sum[:]) }
func Issue(db *gorm.DB,userID string,ttl time.Duration)(string,error){
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 raw:="zzz_"+base64.RawURLEncoding.EncodeToString(b)
 t:=Token{ID:uuid.NewString(),UserID:userID,Hash:Hash(raw),ExpiresAt:time.Now().UTC().Add(ttl)}
 if err:=db.Create(&t).Error;err!=nil{return "",err}
 return raw,nil
}
// IssueForDevice creates a development session restricted to a verified device.
func IssueForDevice(db *gorm.DB,userID,deviceID string,ttl time.Duration)(string,error){
 var device models.Device
 if err:=db.Where("id = ? AND user_id = ? AND verified_at IS NOT NULL AND revoked_at IS NULL",deviceID,userID).First(&device).Error;err!=nil{return "",errors.New("device not verified")}
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 raw:="zzz_"+base64.RawURLEncoding.EncodeToString(b)
 session:=Token{ID:uuid.NewString(),UserID:userID,DeviceID:&deviceID,Hash:Hash(raw),ExpiresAt:time.Now().UTC().Add(ttl)}
 if err:=db.Create(&session).Error;err!=nil{return "",err}
 return raw,nil
}
func Authenticate(db *gorm.DB,header string)(string,error){
 parts:=strings.Fields(header)
 if len(parts)!=2||!strings.EqualFold(parts[0],"Bearer")||!strings.HasPrefix(parts[1],"zzz_"){return "",errors.New("unauthorized")}
 var token Token
 err:=db.Where("hash = ? AND revoked_at IS NULL AND expires_at > ?",Hash(parts[1]),time.Now().UTC()).First(&token).Error
 if err!=nil{return "",errors.New("unauthorized")}
 if token.DeviceID!=nil {
  var d models.Device
  if err:=db.Where("id = ? AND user_id = ? AND verified_at IS NOT NULL AND revoked_at IS NULL",*token.DeviceID,token.UserID).First(&d).Error;err!=nil{return "",errors.New("unauthorized")}
 }
 var u models.User
 if err:=db.Select("id").First(&u,"id = ?",token.UserID).Error;err!=nil{return "",errors.New("unauthorized")}
 return u.ID,nil
}
