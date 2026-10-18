package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestHistoricalRotationAcknowledgements(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 cipher:=bytes.Repeat([]byte{8},32)
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"Vault",KeyEpoch:2},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"u",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{2},32)},
  &models.ItemRevision{VaultID:"v",ItemID:"item",Revision:1,KeyEpoch:1},
  &models.DeviceKeyEnvelope{ID:"old",VaultID:"v",DeviceID:"d",KeyEpoch:1,CryptoVersion:1,Ciphertext:cipher},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(method,path string,payload []byte)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewReader(payload))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if got:=call("POST","/api/v1/vaults/v/rotation/prepare",nil).Code;got!=201{t.Fatalf("prepare: %d",got)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"vault_id = ?","v").Error;err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256(cipher)
 hash:=hex.EncodeToString(digest[:])
 route:="/api/v1/vaults/v/rotation/history-ack"
 send:=func(signature []byte)int{
  body,_:=json.Marshal(map[string]any{"device_id":"d","key_epoch":uint64(1),"envelope_sha256":hash,"signature":signature})
  return call("POST",route,body).Code
 }
 if got:=send(bytes.Repeat([]byte{0},64));got==201{t.Fatal("forged signature accepted")}
 signature:=ed25519.Sign(key,historicalAckMessage(rotation,"d",1,hash))
 if got:=send(signature);got!=201{t.Fatalf("valid history ack: %d",got)}
 recipients:=[]models.RotationRecipient{}
 if err:=db.Where("rotation_id = ?",rotation.ID).Find(&recipients).Error;err!=nil{t.Fatal(err)}
 count,err:=historicalAckCoverage(db,rotation,recipients,[]uint64{1})
 if err!=nil||count!=1{t.Fatalf("valid count %d err %v",count,err)}
 if err:=db.Model(&models.DeviceKeyEnvelope{}).Where("id = ?","old").Update("ciphertext",bytes.Repeat([]byte{9},32)).Error;err!=nil{t.Fatal(err)}
 count,err=historicalAckCoverage(db,rotation,recipients,[]uint64{1})
 if err!=nil||count!=0{t.Fatalf("changed ciphertext valid count %d err %v",count,err)}
}
