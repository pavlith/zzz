package api

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "net/http"
 "strings"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/service"
 "gorm.io/gorm"
)

var errOperationReuse = errors.New("operation identifier reused")

type pushRequest struct {
 OperationID string `json:"operation_id"`
 Type string `json:"type"`
 ItemID string `json:"item_id"`
 ExpectedRevision uint64 `json:"expected_revision"`
 Nonce []byte `json:"nonce"`
 Ciphertext []byte `json:"ciphertext"`
 CryptoVersion uint32 `json:"crypto_version"`
 KeyEpoch uint64 `json:"key_epoch"`
}

// pushSync atomically applies one client mutation and records its idempotency key.
// Clients must use a fresh operation_id whenever the requested content changes.
func(a *API) pushSync(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Write){return}
 var input pushRequest
 if err:=decode(r,&input);err!=nil{problem(w,400,"invalid_json");return}
 if _,err:=uuid.Parse(input.OperationID);err!=nil{problem(w,400,"invalid_operation_id");return}
 if input.Type!="upsert"&&input.Type!="delete"{problem(w,400,"invalid_operation");return}
 if input.Type=="delete"&&(input.ItemID==""||input.ExpectedRevision==0){problem(w,400,"invalid_delete");return}
 if input.Type=="upsert"&&(len(input.Ciphertext)==0||len(input.Nonce)==0||input.CryptoVersion==0){problem(w,400,"invalid_ciphertext");return}
 if input.KeyEpoch!=0 {
  var vault models.Vault
  if err:=a.db.First(&vault,"id = ?",vaultID).Error;err!=nil{failure(w,err);return}
  if vault.KeyEpoch!=input.KeyEpoch{problem(w,409,"key_epoch_mismatch");return}
 }
 if strings.TrimSpace(input.ItemID)==""&&input.ExpectedRevision!=0{problem(w,400,"invalid_revision");return}
 raw,_:=json.Marshal(input)
 sum:=sha256.Sum256(raw)
 digest:=hex.EncodeToString(sum[:])
 var result models.SyncOperation
 replay:=false
 err:=a.db.Transaction(func(tx *gorm.DB)error{
  q:=tx.Where("user_id = ? AND vault_id = ? AND operation_id = ?",userID,vaultID,input.OperationID).First(&result)
  if q.Error==nil{
   if result.RequestHash!=digest{return errOperationReuse}
   replay=true
   return nil
  }
  if !errors.Is(q.Error,gorm.ErrRecordNotFound){return q.Error}
  var itemID string
  var revision uint64
  svc:=service.New(tx)
  if input.Type=="delete"{
   version,err:=svc.DeleteItem(userID,vaultID,input.ItemID,input.ExpectedRevision)
   if err!=nil{return err}
   revision=version
   itemID=input.ItemID
  }else{
   item:=&models.Item{ID:input.ItemID,VaultID:vaultID,Nonce:input.Nonce,Ciphertext:input.Ciphertext,CryptoVersion:input.CryptoVersion}
   if err:=svc.PutItem(userID,item,input.ExpectedRevision);err!=nil{return err}
   itemID=item.ID
   revision=item.Revision
  }
  result=models.SyncOperation{ID:uuid.NewString(),UserID:userID,VaultID:vaultID,OperationID:input.OperationID,RequestHash:digest,ItemID:itemID,Revision:revision}
  return tx.Create(&result).Error
 })
 if err!=nil{
  if err==errOperationReuse{problem(w,409,"operation_id_reused");return}
  failure(w,err);return
 }
 write(w,200,map[string]any{"item_id":result.ItemID,"revision":result.Revision,"replayed":replay})
}
