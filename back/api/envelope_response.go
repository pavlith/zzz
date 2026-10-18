package api

import (
 "encoding/json"
 "time"

 "github.com/pavlith/zzz/back/models"
)

// keyEnvelopeResponse is the candidate-v1 public wire format. Internal SQLite
// column names (ciphertext, crypto_version) must not leak into API responses.
type keyEnvelopeResponse struct {
 ID string `json:"id"`
 VaultID string `json:"vault_id"`
 DeviceID string `json:"device_id"`
 KeyEpoch uint64 `json:"key_epoch"`
 Envelope json.RawMessage `json:"envelope"`
 CreatedAt time.Time `json:"created_at"`
}

func envelopeResponse(record models.DeviceKeyEnvelope) (keyEnvelopeResponse,error) {
 parsed,err:=parseCandidateEnvelope(record.Ciphertext,record.VaultID,record.DeviceID,record.KeyEpoch)
 if err!=nil{return keyEnvelopeResponse{},err}
 wire,err:=canonicalCandidateEnvelope(parsed)
 if err!=nil{return keyEnvelopeResponse{},err}
 return keyEnvelopeResponse{
  ID:record.ID,VaultID:record.VaultID,DeviceID:record.DeviceID,
  KeyEpoch:record.KeyEpoch,Envelope:json.RawMessage(wire),CreatedAt:record.CreatedAt,
 },nil
}

func envelopeResponses(records []models.DeviceKeyEnvelope)([]keyEnvelopeResponse,error){
 out:=make([]keyEnvelopeResponse,0,len(records))
 for _,record:=range records{
  item,err:=envelopeResponse(record);if err!=nil{return nil,err}
  out=append(out,item)
 }
 return out,nil
}
