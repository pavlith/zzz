package api

import (
 "errors"

 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/service"
 "gorm.io/gorm"
)

var errItemKeyEpoch = errors.New("item key epoch mismatch")

// writeItemAtEpoch applies the legacy Item API mutation with an epoch check
// in the same SQLite transaction as the encrypted item update.
func (a *API) writeItemAtEpoch(userID string,item *models.Item,expected,epoch uint64)error{
 if epoch==0{return errItemKeyEpoch}
 return a.db.Transaction(func(tx *gorm.DB)error{
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",item.VaultID).Error;err!=nil{return err}
  if vault.KeyEpoch!=epoch{return errItemKeyEpoch}
  return service.New(tx).PutItem(userID,item,expected)
 })
}
