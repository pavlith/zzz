package cli

import (
 "testing"
 "time"

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestFirstDeviceBootstrap(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,object:=range []any{
  &models.User{ID:"user",Email:"user@invalid.test"},
  &models.Device{ID:"verified",UserID:"user",Name:"First",VerifiedAt:&now,SigningPublicKey:make([]byte,32),EncryptionPublicKey:make([]byte,32)},
  &models.Device{ID:"unverified",UserID:"user",Name:"Second",SigningPublicKey:make([]byte,32),EncryptionPublicKey:make([]byte,32)},
 }{if err:=db.Create(object).Error;err!=nil{t.Fatal(err)}}
 if err:=bootstrapFirstDevice(db,"user","unverified");err==nil{t.Fatal("unverified device trusted")}
 if err:=bootstrapFirstDevice(db,"user","verified");err!=nil{t.Fatal(err)}
 var device models.Device
 if err:=db.First(&device,"id = ?","verified").Error;err!=nil{t.Fatal(err)}
 if device.TrustedAt==nil{t.Fatal("device not trusted")}
 if err:=bootstrapFirstDevice(db,"user","unverified");err==nil{t.Fatal("second bootstrap accepted")}
 if err:=bootstrapFirstDevice(db,"user","verified");err==nil{t.Fatal("repeat bootstrap accepted")}
}
