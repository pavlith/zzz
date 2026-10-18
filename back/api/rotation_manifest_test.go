package api

import (
 "bytes"
 "encoding/json"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestRotationRecipientManifest(t *testing.T) {
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 now:=time.Now().UTC()
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:"v",WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:"v",PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:"first",UserID:"u",Name:"First",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:bytes.Repeat([]byte{2},32)},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 request:=func(method,path,body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 if r:=request("POST","/api/v1/vaults/v/rotation/prepare","");r.Code!=201{t.Fatalf("prepare: %d %s",r.Code,r.Body)}
 second:=models.Device{ID:"second",UserID:"u",Name:"Second",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{3},32),EncryptionPublicKey:bytes.Repeat([]byte{4},32)}
 if err:=db.Create(&second).Error;err!=nil{t.Fatal(err)}
 status:=request("GET","/api/v1/vaults/v/rotation","")
 if status.Code!=200{t.Fatalf("rotation readiness: %d",status.Code)}
 var check struct{Unlisted []string `json:"unlisted_device_ids"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(status.Body.Bytes(),&check);err!=nil{t.Fatal(err)}
 if len(check.Unlisted)!=1||check.Unlisted[0]!="second"||check.Complete{t.Fatalf("manifest drift: %+v",check)}
 envelope:=func(device string)string{
  payload,_:=json.Marshal(map[string]any{"device_id":device,"key_epoch":2,"crypto_version":1,"ciphertext":bytes.Repeat([]byte{7},32)})
  return string(payload)
 }
 if got:=request("POST","/api/v1/vaults/v/key-envelopes",envelope("second")).Code;got!=409{t.Fatalf("later recipient accepted: %d",got)}
 if got:=request("POST","/api/v1/vaults/v/key-envelopes",envelope("first")).Code;got!=201{t.Fatalf("manifest recipient rejected: %d",got)}
 var count int64
 if err:=db.Model(&models.RotationRecipient{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("manifest size: %d",count)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"vault_id = ? AND status = ?","v","prepared").Error;err!=nil{t.Fatal(err)}
 if len(rotation.ManifestSHA256)!=64{t.Fatal("missing manifest digest")}
 if err:=db.Model(&models.RotationRecipient{}).Where("rotation_id = ? AND device_id = ?",rotation.ID,"first").Update("signing_key_sha256","modified").Error;err!=nil{t.Fatal(err)}
 tampered:=request("GET","/api/v1/vaults/v/rotation","")
 if tampered.Code!=200{t.Fatalf("tampered status: %d",tampered.Code)}
 var integrity struct{Valid bool `json:"manifest_valid"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(tampered.Body.Bytes(),&integrity);err!=nil{t.Fatal(err)}
 if integrity.Valid||integrity.Complete{t.Fatal("tampered recipient manifest considered valid")}
 if err:=db.Model(&models.Device{}).Where("id = ?","first").Update("encryption_public_key",bytes.Repeat([]byte{9},32)).Error;err!=nil{t.Fatal(err)}
 changed:=request("GET","/api/v1/vaults/v/rotation","")
 if changed.Code!=200{t.Fatalf("key drift status: %d",changed.Code)}
 var changedState struct{Invalid []string `json:"invalid_device_ids"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(changed.Body.Bytes(),&changedState);err!=nil{t.Fatal(err)}
 if len(changedState.Invalid)!=1||changedState.Invalid[0]!="first"||changedState.Complete{t.Fatalf("undetected recipient key replacement: %+v",changedState)}
}
