package api

import (
 "net/http"
 "time"

 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/models"
)

func (a *API) listDevices(w http.ResponseWriter, r *http.Request, userID string) {
 var devices []models.Device
 if err := a.db.Where("user_id = ?", userID).Order("created_at").Find(&devices).Error; err != nil {
  failure(w, err); return
 }
 write(w, http.StatusOK, devices)
}

func (a *API) createDevice(w http.ResponseWriter, r *http.Request, userID string) {
 var input struct {
  Name string `json:"name"`
  EncryptionPublicKey []byte `json:"encryption_public_key"`
  SigningPublicKey []byte `json:"signing_public_key"`
 }
 if err := decode(r, &input); err != nil || len(input.Name) == 0 || len(input.Name) > 128 ||
  len(input.EncryptionPublicKey) != 32 || len(input.SigningPublicKey) != 32 {
  problem(w, http.StatusBadRequest, "invalid_device"); return
 }
 device := models.Device{
  ID: uuid.NewString(), UserID: userID, Name: input.Name,
  EncryptionPublicKey: input.EncryptionPublicKey, SigningPublicKey: input.SigningPublicKey,
 }
 if err := a.db.Create(&device).Error; err != nil { failure(w, err); return }
 write(w, http.StatusCreated, device)
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request, userID string) {
 now := time.Now().UTC()
 result := a.db.Model(&models.Device{}).
  Where("id = ? AND user_id = ? AND revoked_at IS NULL", r.PathValue("device"), userID).
  Update("revoked_at", &now)
 if result.Error != nil { failure(w, result.Error); return }
 if result.RowsAffected == 0 { problem(w, http.StatusNotFound, "not_found"); return }
 write(w, http.StatusOK, map[string]bool{"ok": true})
}
