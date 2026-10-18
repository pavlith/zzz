package service

import (
 "errors"
 "time"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

var ErrRevisionConflict = errors.New("revision conflict or item not found")

// DeleteItem marks an encrypted item deleted, retaining its identity and revision.
func(s *Service) DeleteItem(actorID,vaultID,itemID string,expected uint64)(uint64,error){
 if expected==0{return 0,errors.New("expected revision required")}
 allowed,err:=acl.Allowed(s.DB,actorID,vaultID,acl.Write)
 if err!=nil{return 0,err}
 if !allowed{return 0,acl.ErrForbidden}
 revision:=expected+1
 err=s.DB.Transaction(func(tx *gorm.DB)error{
  now:=time.Now().UTC()
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",vaultID).Error;err!=nil{return err}
  res:=tx.Model(&models.Item{}).
   Where("id = ? AND vault_id = ? AND revision = ? AND deleted_at IS NULL",itemID,vaultID,expected).
   Updates(map[string]interface{}{"revision":revision,"deleted_at":now,"updated_at":now})
  if res.Error!=nil{return res.Error}
  if res.RowsAffected!=1{return ErrRevisionConflict}
  if err:=tx.Create(&models.ItemRevision{VaultID:vaultID,ItemID:itemID,Revision:revision,KeyEpoch:vault.KeyEpoch,Deleted:true}).Error;err!=nil{return err}
  return tx.Create(&models.SyncEvent{VaultID:vaultID,ItemID:itemID,Revision:revision,Operation:"delete"}).Error
 })
 if err!=nil{return 0,err}
 return revision,nil
}
