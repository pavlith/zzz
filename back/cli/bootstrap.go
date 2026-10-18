package cli

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "time"

 "github.com/pavlith/zzz/back/config"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
 "github.com/spf13/cobra"
 "gorm.io/gorm"
)

// bootstrapFirstDevice is an operator-only development recovery boundary.
// There is deliberately no corresponding HTTP route.
func bootstrapFirstDevice(db *gorm.DB,userID,deviceID string) error {
 if userID==""||deviceID==""{return errors.New("user and device are required")}
 return db.Transaction(func(tx *gorm.DB)error{
  var n int64
  if err:=tx.Model(&models.Device{}).Where("user_id = ? AND trusted_at IS NOT NULL",userID).Count(&n).Error;err!=nil{return err}
  if n!=0{return errors.New("account already has a trusted device")}
  var target models.Device
  if err:=tx.First(&target,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NULL AND revoked_at IS NULL",deviceID,userID).Error;err!=nil{return err}
  if len(target.SigningPublicKey)!=32||len(target.EncryptionPublicKey)!=32{return errors.New("invalid device public keys")}
  now:=time.Now().UTC()
  result:=tx.Model(&models.Device{}).Where("id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NULL AND revoked_at IS NULL",deviceID,userID).Update("trusted_at",now)
  if result.Error!=nil{return result.Error}
  if result.RowsAffected!=1{return errors.New("device changed during bootstrap")}
  return nil
 })
}

func bootstrapDeviceCommand(configPath *string)*cobra.Command{
 var userID,deviceID,signingFingerprint,encryptionFingerprint string
 command:=&cobra.Command{Use:"bootstrap-device",Short:"Locally trust first verified device (operator only)",RunE:func(cmd *cobra.Command,args []string)error{
  c,err:=config.Load(*configPath);if err!=nil{return err}
  db,err:=database.Open(c.Database.DSN);if err!=nil{return err}
  if err:=database.Migrate(db);err!=nil{return err}
  var device models.Device
  if err:=db.First(&device,"id = ? AND user_id = ?",deviceID,userID).Error;err!=nil{return err}
  signing:=sha256.Sum256(device.SigningPublicKey)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  if hex.EncodeToString(signing[:])!=signingFingerprint||hex.EncodeToString(encryption[:])!=encryptionFingerprint{return errors.New("provided public key fingerprints do not match")}
  if err:=bootstrapFirstDevice(db,userID,deviceID);err!=nil{return err}
  _,err=fmt.Fprintf(cmd.OutOrStdout(),"trusted first device %s for user %s\n",deviceID,userID)
  return err
 }}
 command.Flags().StringVar(&userID,"user","","Existing account identifier")
 command.Flags().StringVar(&deviceID,"device","","Verified device identifier")
 command.Flags().StringVar(&signingFingerprint,"signing-sha256","","Expected SHA-256 of raw signing public key (hex)")
 command.Flags().StringVar(&encryptionFingerprint,"encryption-sha256","","Expected SHA-256 of raw encryption public key (hex)")
 _=command.MarkFlagRequired("user")
 _=command.MarkFlagRequired("device")
 _=command.MarkFlagRequired("signing-sha256")
 _=command.MarkFlagRequired("encryption-sha256")
 return command
}
