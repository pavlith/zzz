package api

import (
 "bytes"
 "encoding/json"
 "encoding/hex"
 "crypto/sha256"
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
 firstPublic,signer:=candidateTestKeys(t)
 secondPublic,_:=candidateTestKeys(t)
 firstID:="22345678-1234-1234-1234-123456789abc"
 secondID:="52345678-1234-1234-1234-123456789abc"
 for _,v:=range []any{
  &models.User{ID:"u",Email:"u@invalid.test"},
  &models.Workspace{ID:"w",Name:"W",Kind:"personal"},
  &models.WorkspaceMember{WorkspaceID:"w",UserID:"u",Role:"owner"},
  &models.Vault{ID:fixtureVaultID,WorkspaceID:"w",Name:"V",KeyEpoch:1},
  &models.VaultPermission{ID:"p",VaultID:fixtureVaultID,PrincipalType:"user",PrincipalID:"u",CanRead:true,CanManage:true},
  &models.Device{ID:firstID,UserID:"u",Name:"First",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{1},32),EncryptionPublicKey:firstPublic},
 }{if err:=db.Create(v).Error;err!=nil{t.Fatal(err)}}
 token,err:=auth.Issue(db,"u",time.Hour);if err!=nil{t.Fatal(err)}
 server:=New(db)
 request:=func(method,path,body string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
  req.Header.Set("Authorization","Bearer "+token)
  req.Header.Set("Content-Type","application/json")
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 if r:=request("POST","/api/v1/vaults/"+fixtureVaultID+"/rotation/prepare","");r.Code!=201{t.Fatalf("prepare: %d %s",r.Code,r.Body)}
 second:=models.Device{ID:secondID,UserID:"u",Name:"Second",VerifiedAt:&now,TrustedAt:&now,SigningPublicKey:bytes.Repeat([]byte{3},32),EncryptionPublicKey:secondPublic}
 if err:=db.Create(&second).Error;err!=nil{t.Fatal(err)}
 status:=request("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation","")
 if status.Code!=200{t.Fatalf("rotation readiness: %d",status.Code)}
 var check struct{Unlisted []string `json:"unlisted_device_ids"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(status.Body.Bytes(),&check);err!=nil{t.Fatal(err)}
 if len(check.Unlisted)!=1||check.Unlisted[0]!=secondID||check.Complete{t.Fatalf("manifest drift: %+v",check)}
 var rotation models.VaultRotation
 if err:=db.First(&rotation,"vault_id = ? AND status = ?",fixtureVaultID,"prepared").Error;err!=nil{t.Fatal(err)}
 envelope:=func(device string)string{
  public:=firstPublic;if device==secondID{public=secondPublic}
  return candidateTestRequest(t,device,2,candidateTestEnvelope(t,fixtureVaultID,device,rotation.ID,firstID,2,public,signer,candidateTestManifest()))
 }
 if got:=request("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",envelope(secondID)).Code;got!=409{t.Fatalf("later recipient accepted: %d",got)}
 if got:=request("POST","/api/v1/vaults/"+fixtureVaultID+"/key-envelopes",envelope(firstID)).Code;got!=201{t.Fatalf("manifest recipient rejected: %d",got)}
 var count int64
 if err:=db.Model(&models.RotationRecipient{}).Count(&count).Error;err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("manifest size: %d",count)}
 if len(rotation.ManifestSHA256)!=64{t.Fatal("missing manifest digest")}
 if err:=db.Model(&models.RotationRecipient{}).Where("rotation_id = ? AND device_id = ?",rotation.ID,firstID).Update("signing_key_sha256","modified").Error;err!=nil{t.Fatal(err)}
 tampered:=request("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation","")
 if tampered.Code!=200{t.Fatalf("tampered status: %d",tampered.Code)}
 var integrity struct{Valid bool `json:"manifest_valid"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(tampered.Body.Bytes(),&integrity);err!=nil{t.Fatal(err)}
 if integrity.Valid||integrity.Complete{t.Fatal("tampered recipient manifest considered valid")}
 if err:=db.Model(&models.Device{}).Where("id = ?",firstID).Update("encryption_public_key",bytes.Repeat([]byte{9},32)).Error;err!=nil{t.Fatal(err)}
 changed:=request("GET","/api/v1/vaults/"+fixtureVaultID+"/rotation","")
 if changed.Code!=200{t.Fatalf("key drift status: %d",changed.Code)}
 var changedState struct{Invalid []string `json:"invalid_device_ids"`;Complete bool `json:"envelopes_complete"`}
 if err:=json.Unmarshal(changed.Body.Bytes(),&changedState);err!=nil{t.Fatal(err)}
 if len(changedState.Invalid)!=1||changedState.Invalid[0]!=firstID||changedState.Complete{t.Fatalf("undetected recipient key replacement: %+v",changedState)}
}
