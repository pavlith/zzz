package service

import (
 "sync"
 "testing"

 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestConflictingItemUpdates(t *testing.T){
 db,err:=database.Open("file:conflict_test?mode=memory&cache=shared")
 if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanWrite:true},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 svc:=New(db)
 seed:=&models.Item{VaultID:"v",Nonce:[]byte("n"),Ciphertext:[]byte("initial"),CryptoVersion:1}
 if err:=svc.PutItem("u",seed,0);err!=nil{t.Fatal(err)}
 var wg sync.WaitGroup
 results:=make(chan error,2)
 for _,payload:=range []string{"device-A","device-B"}{
  wg.Add(1)
  go func(data string){
   defer wg.Done()
   update:=&models.Item{ID:seed.ID,VaultID:"v",Nonce:[]byte("n"),Ciphertext:[]byte(data),CryptoVersion:1}
   results<-svc.PutItem("u",update,1)
  }(payload)
 }
 wg.Wait();close(results)
 success:=0
 for e:=range results{if e==nil{success++}}
 if success!=1{t.Fatalf("expected exactly one committed update, got %d",success)}
 var item models.Item
 if err:=db.First(&item,"id = ?",seed.ID).Error;err!=nil{t.Fatal(err)}
 if item.Revision!=2{t.Fatalf("revision %d",item.Revision)}
 var versions int64
 if err:=db.Model(&models.ItemRevision{}).Where("item_id = ?",seed.ID).Count(&versions).Error;err!=nil{t.Fatal(err)}
 if versions!=2{t.Fatalf("revision history has %d versions",versions)}
}
