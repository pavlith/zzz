package api

import (
 "net/http"
 "crypto/sha256"
 "encoding/hex"
 "crypto/ed25519"

 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/models"
 "gorm.io/gorm"
)

type rotationPreflight struct {
 RotationID string `json:"rotation_id"`
 ManifestValid bool `json:"manifest_valid"`
 EnvelopesComplete bool `json:"envelopes_complete"`
 RequiredApprovals uint32 `json:"required_approvals"`
 ValidApprovals int `json:"valid_approvals"`
 ValidEnvelopeAcks int `json:"valid_envelope_acks"`
 RequiredEnvelopeAcks int `json:"required_envelope_acks"`
 QuorumMet bool `json:"quorum_met"`
 KeyCommitmentConsensus bool `json:"key_commitment_consensus"`
 KeyCommitmentConflict bool `json:"key_commitment_conflict"`
 ValidKeyCommitments int `json:"valid_key_commitments"`
 RequiredKeyCommitments int `json:"required_key_commitments"`
 Blockers []string `json:"blockers"`
 CanActivate bool `json:"can_activate"`
 RequiredHistoricalEpochs []uint64 `json:"required_historical_epochs"`
 MissingHistoricalEnvelopes []missingHistoricalEnvelope `json:"missing_historical_envelopes"`
 HistoricalEnvelopesComplete bool `json:"historical_envelopes_complete"`
 RequiredHistoricalAcks int `json:"required_historical_acks"`
 ValidHistoricalAcks int `json:"valid_historical_acks"`
}

// activationPreflight checks a consistent database snapshot. It deliberately
// makes no state changes and cannot prove client-side envelope decryptability.
func activationPreflight(db *gorm.DB,vaultID string)(rotationPreflight,error){
 out:=rotationPreflight{Blockers:[]string{},CanActivate:false}
 err:=db.Transaction(func(tx *gorm.DB)error{
  var rotation models.VaultRotation
  if err:=tx.First(&rotation,"vault_id = ? AND status = ?",vaultID,"prepared").Error;err!=nil{return err}
  out.RotationID=rotation.ID
  recipient,err:=validateRotation(tx,rotation)
  if err!=nil{return err}
  signatures,err:=validateRotationSignatures(tx,rotation)
  if err!=nil{return err}
  out.ManifestValid=recipient.ManifestValid
  out.EnvelopesComplete=recipient.Complete
  out.RequiredApprovals=rotation.RequiredApprovals
  out.ValidApprovals=signatures.Valid
  out.QuorumMet=rotation.RequiredApprovals>0&&signatures.Valid>=int(rotation.RequiredApprovals)
  if !recipient.ManifestValid{out.Blockers=append(out.Blockers,"manifest_invalid")}
  if !recipient.EpochCurrent{out.Blockers=append(out.Blockers,"epoch_changed")}
  if recipient.Required==0{out.Blockers=append(out.Blockers,"empty_manifest")}
  if len(recipient.Missing)>0{out.Blockers=append(out.Blockers,"envelopes_missing")}
  if len(recipient.Invalid)>0{out.Blockers=append(out.Blockers,"recipients_invalid")}
  if len(recipient.Unlisted)>0{out.Blockers=append(out.Blockers,"recipients_unlisted")}
  if !out.QuorumMet{out.Blockers=append(out.Blockers,"quorum_not_met")}
  var recipients []models.RotationRecipient
  if err:=tx.Where("rotation_id = ?",rotation.ID).Find(&recipients).Error;err!=nil{return err}
  comparison,err:=compareRotationCommitments(tx,rotation,recipients)
  if err!=nil{return err}
  out.KeyCommitmentConsensus=comparison.Consensus
  out.KeyCommitmentConflict=comparison.Conflicting
  out.ValidKeyCommitments=comparison.Valid
  out.RequiredKeyCommitments=comparison.Required
  if comparison.Conflicting{out.Blockers=append(out.Blockers,"key_commitment_conflict")}
  if !comparison.Consensus{out.Blockers=append(out.Blockers,"key_commitments_incomplete")}
  history,err:=historicalEnvelopeCoverage(tx,rotation,recipients)
  if err!=nil{return err}
  out.RequiredHistoricalEpochs=history.RequiredEpochs
  out.MissingHistoricalEnvelopes=history.Missing
  out.HistoricalEnvelopesComplete=history.Complete
  out.RequiredHistoricalAcks=len(recipients)*len(history.RequiredEpochs)
  out.ValidHistoricalAcks,err=historicalAckCoverage(tx,rotation,recipients,history.RequiredEpochs)
  if err!=nil{return err}
  if out.ValidHistoricalAcks!=out.RequiredHistoricalAcks{out.Blockers=append(out.Blockers,"historical_acknowledgements_missing")}
  if !history.Complete{out.Blockers=append(out.Blockers,"historical_envelopes_missing")}
  out.RequiredEnvelopeAcks=len(recipients)
  for _,recipient:=range recipients{
   var ack models.RotationEnvelopeAck
   if err:=tx.First(&ack,"rotation_id = ? AND device_id = ?",rotation.ID,recipient.DeviceID).Error;err!=nil{
    if err==gorm.ErrRecordNotFound{continue};return err
   }
   var device models.Device
   if err:=tx.First(&device,"id = ? AND user_id = ? AND verified_at IS NOT NULL AND trusted_at IS NOT NULL AND revoked_at IS NULL",recipient.DeviceID,recipient.UserID).Error;err!=nil{
    if err==gorm.ErrRecordNotFound{continue};return err
   }
   signing:=sha256.Sum256(device.SigningPublicKey)
   encryption:=sha256.Sum256(device.EncryptionPublicKey)
   if hex.EncodeToString(signing[:])!=recipient.SigningKeySHA256||hex.EncodeToString(encryption[:])!=recipient.EncryptionKeySHA256{continue}
   var envelope models.DeviceKeyEnvelope
   if err:=tx.First(&envelope,"vault_id = ? AND device_id = ? AND key_epoch = ?",rotation.VaultID,recipient.DeviceID,rotation.ToEpoch).Error;err!=nil{
    if err==gorm.ErrRecordNotFound{continue};return err
   }
   digest:=sha256.Sum256(envelope.Ciphertext)
   if hex.EncodeToString(digest[:])!=ack.EnvelopeSHA256{continue}
   if !ed25519.Verify(ed25519.PublicKey(device.SigningPublicKey),envelopeAckMessage(rotation,device.ID,ack.EnvelopeSHA256),ack.Signature){continue}
   out.ValidEnvelopeAcks++
  }
  if out.RequiredEnvelopeAcks==0||out.ValidEnvelopeAcks!=out.RequiredEnvelopeAcks{out.Blockers=append(out.Blockers,"envelope_acknowledgements_missing")}
  // The key cryptographic proof and historical-key retention policies remain missing.
  out.Blockers=append(out.Blockers,"client_decryption_claims_unverifiable","historical_key_access_unverified")
  return nil
 })
 return out,err
}
func(a *API) rotationPreflightEndpoint(w http.ResponseWriter,r *http.Request,userID string){
 vaultID:=r.PathValue("vault")
 if !a.check(w,userID,vaultID,acl.Manage){return}
 result,err:=activationPreflight(a.db,vaultID)
 if err!=nil{failure(w,err);return}
 write(w,http.StatusOK,result)
}
