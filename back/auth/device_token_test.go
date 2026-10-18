package auth

import (
 "bytes"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/models"
 "gorm.io/driver/sqlite"
 "gorm.io/gorm"
)

func TestDeviceBoundToken(t *testing.T) {
 db,err:=gorm.Open(sqlite.Open(":memory:"),&gorm.Config{})
 if err!=nil {t.Fatal(err)}
 if err=db.AutoMigrate(&models.User{},&models.Device{},&Token{});err!=nil{t.Fatal(err)}
 if err=db.Create(&models.User{ID:"u",Email:"u@example.test"}).Error;err!=nil{t.Fatal(err)}
 device:=models.Device{ID:"d",UserID:"u",Name:"desktop",SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:bytes.Repeat([]byte{2},32)}
 if err=db.Create(&device).Error;err!=nil{t.Fatal(err)}
 if _,err=IssueForDevice(db,"u","d",time.Hour);err==nil{t.Fatal("unverified device received token")}
 now:=time.Now().UTC()
 if err=db.Model(&device).Update("verified_at",now).Error;err!=nil{t.Fatal(err)}
 if _,err=IssueForDevice(db,"u","d",time.Hour);err==nil{t.Fatal("untrusted device received token")}
 if err=db.Model(&device).Update("trusted_at",now).Error;err!=nil{t.Fatal(err)}
 token,err:=IssueForDevice(db,"u","d",time.Hour);if err!=nil{t.Fatal(err)}
 if id,err:=Authenticate(db,"Bearer "+token);err!=nil||id!="u"{t.Fatalf("valid session: %q %v",id,err)}
 if err=db.Model(&device).Update("revoked_at",now).Error;err!=nil{t.Fatal(err)}
 if _,err:=Authenticate(db,"Bearer "+token);err==nil{t.Fatal("revoked device session accepted")}
}
