package api

import (
 "bytes"
 "encoding/json"

 candidate "github.com/pavlith/zzz/pkgs/e2ee/candidatev1"
)

// parseCandidateEnvelope rejects legacy opaque payloads, duplicate members,
// unknown fields and envelopes bound to another vault/device/epoch.
// This is structural validation only: signer trust and manifest authorization
// must be established independently by clients.
func parseCandidateEnvelope(payload []byte,vaultID,deviceID string,epoch uint64)(candidate.Envelope,error){
 e,err:=candidate.Parse(payload)
 if err!=nil{return e,err}
 if e.VaultID!=vaultID||e.DeviceID!=deviceID||e.KeyEpoch!=epoch{
  return candidate.Envelope{},candidate.ErrInvalid
 }
 // Only canonical candidate-v1 JSON is persisted. Whitespace/key order on
 // input is accepted, but the validated envelope is normalized on write.
 return e,nil
}

func canonicalCandidateEnvelope(e candidate.Envelope)([]byte,error){
 return json.Marshal(e)
}

func decodeCandidateEnvelopeRequest(raw json.RawMessage,vaultID,deviceID string,epoch uint64)([]byte,error){
 e,err:=parseCandidateEnvelope(bytes.TrimSpace(raw),vaultID,deviceID,epoch)
 if err!=nil{return nil,err}
 return canonicalCandidateEnvelope(e)
}
