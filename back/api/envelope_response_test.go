package api

import (
 "encoding/json"
 "testing"

 "github.com/pavlith/zzz/back/models"
)

func TestCandidateEnvelopeResponseContract(t *testing.T){
 recipient,signer:=candidateTestKeys(t)
 wire:=candidateTestEnvelope(t,fixtureVaultID,fixtureDeviceID,fixtureRotationID,fixtureSignerID,1,recipient,signer,candidateTestManifest())
 record:=models.DeviceKeyEnvelope{ID:"record",VaultID:fixtureVaultID,DeviceID:fixtureDeviceID,KeyEpoch:1,CryptoVersion:1,Envelope:wire}
 result,err:=envelopeResponse(record);if err!=nil{t.Fatal(err)}
 if result.DeviceID!=fixtureDeviceID||len(result.Envelope)==0{t.Fatalf("invalid response: %+v",result)}
 b,err:=json.Marshal(result);if err!=nil{t.Fatal(err)}
 var obj map[string]json.RawMessage
 if err:=json.Unmarshal(b,&obj);err!=nil{t.Fatal(err)}
 if _,ok:=obj["ciphertext"];ok{t.Fatal("legacy ciphertext leaked")}
 if _,ok:=obj["crypto_version"];ok{t.Fatal("legacy crypto version leaked")}
 if _,ok:=obj["envelope"];!ok{t.Fatal("candidate envelope omitted")}
 var nested map[string]json.RawMessage
 if err:=json.Unmarshal(obj["envelope"],&nested);err!=nil{t.Fatal(err)}
 for _,field:=range []string{"protocol","suite","vault_id","device_id","rotation_id","key_epoch","recipient_key_sha256","ephemeral_public_key","nonce","ciphertext","manifest_sha256","vault_key_commitment","signer_device_id","signature"}{
  if _,ok:=nested[field];!ok{t.Fatalf("candidate envelope missing %s",field)}
 }
 if _,ok:=obj["created_at"];!ok{t.Fatal("created_at omitted")}
 record.Envelope=[]byte("invalid")
 if _,err:=envelopeResponse(record);err==nil{t.Fatal("corrupt stored envelope accepted")}
}
