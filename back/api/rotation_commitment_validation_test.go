package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "crypto/rand"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationKeyCommitmentConflict(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 if err:=db.Create(&models.User{ID:"u",Email:"u@invalid.test"}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.Workspace{ID:"w",Name:"W",Kind:"personal"}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1}).Error;err!=nil{t.Fatal(err)}
 if err:=db.Create(&models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true}).Error;err!=nil{t.Fatal(err)}
 _=acl.Read
 rotation:=models.VaultRotation{ID:"rot",VaultID:"v",FromEpoch:1,ToEpoch:2,Status:"prepared",ManifestSHA256:"manifest"}
 if err:=db.Create(&rotation).Error;err!=nil{t.Fatal(err)}
 var recipients []models.RotationRecipient
 for _,id:=range []string{"d1","d2"}{
  pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  device:=models.Device{ID:id,UserID:"u",Name:id,VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:pub,EncryptionPublicKey:bytes.Repeat([]byte{4},32)}
  if err:=db.Create(&device).Error;err!=nil{t.Fatal(err)}
  signing:=sha256.Sum256(pub)
  encryption:=sha256.Sum256(device.EncryptionPublicKey)
  recipient:=models.RotationRecipient{RotationID:"rot",DeviceID:id,UserID:"u",SigningKeySHA256:hex.EncodeToString(signing[:]),EncryptionKeySHA256:hex.EncodeToString(encryption[:])}
  if err:=db.Create(&recipient).Error;err!=nil{t.Fatal(err)}
  recipients=append(recipients,recipient)
  hash:="same"
  if id=="d2"{hash="different"}
  signature:=ed25519.Sign(priv,rotationCommitmentMessage(rotation,id,hash))
  if err:=db.Create(&models.RotationCommitment{RotationID:"rot",DeviceID:id,ManifestSHA256:rotation.ManifestSHA256,KeyCommitment:hash,Signature:signature}).Error;err!=nil{t.Fatal(err)}
 }
 result,err:=compareRotationCommitments(db,rotation,recipients)
 if err!=nil{t.Fatal(err)}
 if !result.Conflicting||result.Consensus||result.Valid!=2{t.Fatalf("conflict undetected: %+v",result)}
}
