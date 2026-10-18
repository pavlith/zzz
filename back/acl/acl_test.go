package acl

import (
 "testing"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)
func TestGroupGrantWorkspaceIsolation(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,v:=range []interface{}{
  &models.Workspace{ID:"w1",Name:"one",Kind:"team"},
  &models.Workspace{ID:"w2",Name:"two",Kind:"team"},
  &models.WorkspaceMember{WorkspaceID:"w1",UserID:"alice",Role:"member"},
  &models.Group{ID:"g1",WorkspaceID:"w1",Name:"team"},
  &models.GroupMember{GroupID:"g1",UserID:"alice"},
  &models.Vault{ID:"v1",WorkspaceID:"w1",Name:"test"},
  &models.Vault{ID:"v2",WorkspaceID:"w2",Name:"other"},
  &models.VaultPermission{ID:"p1",VaultID:"v1",PrincipalType:"group",PrincipalID:"g1",CanRead:true},
  &models.VaultPermission{ID:"p2",VaultID:"v2",PrincipalType:"group",PrincipalID:"g1",CanRead:true},
 } {if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 ok,err:=Allowed(db,"alice","v1",Read);if err!=nil||!ok{t.Fatalf("expected read: %v %v",ok,err)}
 ok,err=Allowed(db,"alice","v1",Write);if err!=nil||ok{t.Fatalf("unexpected write: %v %v",ok,err)}
 ok,err=Allowed(db,"alice","v2",Read);if err!=nil||ok{t.Fatalf("cross workspace access: %v %v",ok,err)}
}
