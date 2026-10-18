package service

import (
 "errors"
 "fmt"
 "time"
 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type Service struct { DB *gorm.DB }
func New(db *gorm.DB)*Service{return &Service{DB:db}}
func (s *Service) CreateWorkspace(ownerID,name,kind string)(*models.Workspace,error){
 if name=="" {return nil,errors.New("workspace name required")}
 w:=&models.Workspace{ID:uuid.NewString(),Name:name,Kind:kind}
 err:=s.DB.Transaction(func(tx *gorm.DB)error{
  if err:=tx.Create(w).Error;err!=nil{return err}
  return tx.Create(&models.WorkspaceMember{WorkspaceID:w.ID,UserID:ownerID,Role:"owner"}).Error
 })
 return w,err
}
func (s *Service) CreateGroup(actorID,workspaceID,name string)(*models.Group,error){
 if name=="" {return nil,errors.New("group name required")}
 if err:=requireAdmin(s.DB,actorID,workspaceID);err!=nil{return nil,err}
 g:=&models.Group{ID:uuid.NewString(),WorkspaceID:workspaceID,Name:name}
 return g,s.DB.Create(g).Error
}
func (s *Service) AddGroupMember(actorID,groupID,userID string)error{
 var g models.Group
 if err:=s.DB.First(&g,"id = ?",groupID).Error;err!=nil{return err}
 if err:=requireAdmin(s.DB,actorID,g.WorkspaceID);err!=nil{return err}
 var n int64
 if err:=s.DB.Model(&models.WorkspaceMember{}).Where("workspace_id = ? AND user_id = ?",g.WorkspaceID,userID).Count(&n).Error;err!=nil{return err}
 if n==0{return acl.ErrForbidden}
 return s.DB.Create(&models.GroupMember{GroupID:groupID,UserID:userID}).Error
}
func (s *Service) CreateVault(actorID,workspaceID,name string)(*models.Vault,error){
 if err:=requireAdmin(s.DB,actorID,workspaceID);err!=nil{return nil,err}
 if name==""{return nil,errors.New("vault name required")}
 v:=&models.Vault{ID:uuid.NewString(),WorkspaceID:workspaceID,Name:name,KeyEpoch:1}
 return v,s.DB.Create(v).Error
}
func (s *Service) Grant(actorID string,p models.VaultPermission)error{
 var v models.Vault
 if err:=s.DB.First(&v,"id = ?",p.VaultID).Error;err!=nil{return err}
 if err:=requireAdmin(s.DB,actorID,v.WorkspaceID);err!=nil{return err}
 var count int64
 switch p.PrincipalType {
 case "user":
  s.DB.Model(&models.WorkspaceMember{}).Where("workspace_id = ? AND user_id = ?",v.WorkspaceID,p.PrincipalID).Count(&count)
 case "group":
  s.DB.Model(&models.Group{}).Where("id = ? AND workspace_id = ?",p.PrincipalID,v.WorkspaceID).Count(&count)
 default: return fmt.Errorf("invalid principal type")
 }
 if count==0{return acl.ErrForbidden}
 p.ID=uuid.NewString()
 return s.DB.Create(&p).Error
}
func (s *Service) PutItem(actorID string, item *models.Item,expectedRevision uint64)error{
 allowed,err:=acl.Allowed(s.DB,actorID,item.VaultID,acl.Write)
 if err!=nil{return err}
 if !allowed{return acl.ErrForbidden}
 if len(item.Ciphertext)==0||len(item.Nonce)==0||item.CryptoVersion==0{return errors.New("encrypted payload required")}
 now:=time.Now().UTC()
 return s.DB.Transaction(func(tx *gorm.DB)error{
  var vault models.Vault
  if err:=tx.First(&vault,"id = ?",item.VaultID).Error;err!=nil{return err}
  if item.ID=="" {
   if expectedRevision!=0{return errors.New("new item expected revision must be zero")}
   item.ID=uuid.NewString();item.Revision=1;item.CreatedAt=now;item.UpdatedAt=now
   if err:=tx.Create(item).Error;err!=nil{return err}
   if err:=tx.Create(&models.ItemRevision{VaultID:item.VaultID,ItemID:item.ID,Revision:1,KeyEpoch:vault.KeyEpoch,Nonce:item.Nonce,Ciphertext:item.Ciphertext,CryptoVersion:item.CryptoVersion}).Error;err!=nil{return err}
   return tx.Create(&models.SyncEvent{VaultID:item.VaultID,ItemID:item.ID,Revision:1,Operation:"upsert"}).Error
  }
  if expectedRevision==0{return errors.New("existing item requires revision")}
  updates:=map[string]interface{}{"revision":expectedRevision+1,"nonce":item.Nonce,"ciphertext":item.Ciphertext,"crypto_version":item.CryptoVersion,"updated_at":now}
  res:=tx.Model(&models.Item{}).Where("id = ? AND vault_id = ? AND revision = ? AND deleted_at IS NULL",item.ID,item.VaultID,expectedRevision).Updates(updates)
  if res.Error!=nil{return res.Error}
  if res.RowsAffected==0{return errors.New("revision conflict or item not found")}
  item.Revision=expectedRevision+1
  if err:=tx.Create(&models.ItemRevision{VaultID:item.VaultID,ItemID:item.ID,Revision:item.Revision,KeyEpoch:vault.KeyEpoch,Nonce:item.Nonce,Ciphertext:item.Ciphertext,CryptoVersion:item.CryptoVersion}).Error;err!=nil{return err}
  return tx.Create(&models.SyncEvent{VaultID:item.VaultID,ItemID:item.ID,Revision:item.Revision,Operation:"upsert"}).Error
 })
}
func requireAdmin(db *gorm.DB,actorID,workspaceID string)error{
 var m models.WorkspaceMember
 err:=db.First(&m,"workspace_id = ? AND user_id = ?",workspaceID,actorID).Error
 if errors.Is(err,gorm.ErrRecordNotFound){return acl.ErrForbidden}
 if err!=nil{return err}
 if m.Role!="owner"&&m.Role!="admin"{return acl.ErrForbidden}
 return nil
}
