package api

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestSignedRotationManifest(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,record:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"d",UserID:"u",Name:"Trusted",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:public,EncryptionPublicKey:bytes.Repeat([]byte{3},32)},
 }{if err:=db.Create(record).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(path string,body []byte)*httptest.ResponseRecorder{
  req:=httptest.NewRequest("POST",path,bytes.NewReader(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  rec:=httptest.NewRecorder();server.ServeHTTP(rec,req);return rec
 }
 if result:=call("/api/v1/vaults/v/rotation/prepare",nil);result.Code!=201{t.Fatalf("prepare: %d %s",result.Code,result.Body)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"vault_id = ? AND status = ?","v","prepared").Error;err!=nil{t.Fatal(err)}
 input:=func(sig []byte)[]byte{
  payload,_:=json.Marshal(map[string]any{"device_id":"d","manifest_sha256":rotation.ManifestSHA256,"signature":base64.StdEncoding.EncodeToString(sig)})
  return payload
 }
 route:="/api/v1/vaults/v/rotation/sign"
 if got:=call(route,input(make([]byte,64))).Code;got!=400{t.Fatalf("forged signature accepted: %d",got)}
 signature:=ed25519.Sign(private,rotationSignMessage(rotation))
 if got:=call(route,input(signature)).Code;got!=201{t.Fatalf("valid signature rejected: %d",got)}
 if got:=call(route,input(signature)).Code;got==201{t.Fatal("duplicate signature accepted")}
 var approved int64
 if err:=db.Model(&models.RotationSignature{}).Where("rotation_id = ?",rotation.ID).Count(&approved).Error;err!=nil{t.Fatal(err)}
 if approved!=1{t.Fatalf("approval count: %d",approved)}
 statusReq:=httptest.NewRequest("GET","/api/v1/vaults/v/rotation",nil)
 statusReq.Header.Set("Authorization","Bearer "+token)
 statusRec:=httptest.NewRecorder();server.ServeHTTP(statusRec,statusReq)
 if statusRec.Code!=200{t.Fatalf("quorum status: %d",statusRec.Code)}
 var status struct{Required uint32 `json:"required_approvals"`;Met bool `json:"quorum_met"`;Valid int `json:"valid_signature_count"`}
 if err:=json.Unmarshal(statusRec.Body.Bytes(),&status);err!=nil{t.Fatal(err)}
 if status.Required!=1||!status.Met||status.Valid!=1{t.Fatalf("unexpected quorum: %+v",status)}
 valid,err:=validateRotationSignatures(db,rotation);if err!=nil{t.Fatal(err)}
 if valid.Valid!=1||valid.Total!=1{t.Fatalf("valid approvals: %+v",valid)}
 if err:=db.Model(&models.Device{}).Where("id = ?","d").Update("revoked_at",now).Error;err!=nil{t.Fatal(err)}
 revoked,err:=validateRotationSignatures(db,rotation);if err!=nil{t.Fatal(err)}
 if revoked.Valid!=0||len(revoked.InvalidDeviceIDs)!=1{t.Fatalf("revoked signer counted: %+v",revoked)}
 if err:=db.Model(&models.Device{}).Where("id = ?","d").Update("revoked_at",nil).Error;err!=nil{t.Fatal(err)}
 if err:=db.Model(&models.Device{}).Where("id = ?","d").Update("signing_public_key",bytes.Repeat([]byte{9},32)).Error;err!=nil{t.Fatal(err)}
 changed,err:=validateRotationSignatures(db,rotation);if err!=nil{t.Fatal(err)}
 if changed.Valid!=0{t.Fatalf("changed signer key counted: %+v",changed)}
}
