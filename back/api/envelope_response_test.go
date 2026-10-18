package api

import (
 "encoding/json"
 "testing"

 "github.com/pavlith/zzz/back/models"
)

func TestCandidateEnvelopeResponseContract(t *testing.T){
 recipient,signer:=candidateTestKeys(t)
 wire:=candidateTestEnvelope(t,fixtureVaultID,fixtureDeviceID,fixtureRotationID,fixtureSignerID,1,recipient,signer,candidateTestManifest())
 record:=models.DeviceKeyEnvelope{ID:"record",VaultID:fixtureVaultID,DeviceID:fixtureDeviceID,KeyEpoch:1,CryptoVersion:1,Ciphertext:wire}
 result,err:=envelopeResponse(record);if err!=nil{t.Fatal(err)}
 if result.DeviceID!=fixtureDeviceID||len(result.Envelope)==0{t.Fatalf("invalid response: %+v",result)}
 b,err:=json.Marshal(result);if err!=nil{t.Fatal(err)}
 var obj map[string]json.RawMessage
 if err:=json.Unmarshal(b,&obj);err!=nil{t.Fatal(err)}
 if _,ok:=obj["ciphertext"];ok{t.Fatal("legacy ciphertext leaked")}
 if _,ok:=obj["crypto_version"];ok{t.Fatal("legacy crypto version leaked")}
 if _,ok:=obj["envelope"];!ok{t.Fatal("candidate envelope omitted")}
 record.Ciphertext=[]byte("invalid")
 if _,err:=envelopeResponse(record);err==nil{t.Fatal("corrupt stored envelope accepted")}
}
