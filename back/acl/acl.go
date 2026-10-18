package acl

import (
 "errors"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)
var ErrForbidden=errors.New("permission denied")
type Action string
const ( Read Action="read"; Write Action="write"; Manage Action="manage" )

// Allowed requires workspace membership and an explicit vault grant.
// Owners/admins do not bypass vault encryption or grant checks.
func Allowed(db *gorm.DB, userID,vaultID string, action Action)(bool,error){
 var vault models.Vault
 if err:=db.First(&vault,"id = ?",vaultID).Error;err!=nil{return false,err}
 var member models.WorkspaceMember
 if err:=db.First(&member,"workspace_id = ? AND user_id = ?",vault.WorkspaceID,userID).Error;err!=nil {
  if errors.Is(err,gorm.ErrRecordNotFound){return false,nil};return false,err
 }
 var grants []models.VaultPermission
 err:=db.Model(&models.VaultPermission{}).
  Where("vault_id = ? AND ((principal_type = ? AND principal_id = ?) OR (principal_type = ? AND principal_id IN (SELECT gm.group_id FROM group_members gm JOIN groups g ON g.id = gm.group_id WHERE gm.user_id = ? AND g.workspace_id = ?)))",vaultID,"user",userID,"group",userID,vault.WorkspaceID).
  Find(&grants).Error
 if err!=nil{return false,err}
 for _,p:=range grants {
  if action==Read&&(p.CanRead||p.CanWrite||p.CanManage) ||
   action==Write&&(p.CanWrite||p.CanManage) ||
   action==Manage&&p.CanManage {return true,nil}
 }
 return false,nil
}
