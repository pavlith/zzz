package models

import "time"

// Device public keys are metadata. Device private keys never belong on the server.
type Device struct {
    ID string `gorm:"primaryKey;size:36" json:"id"`
    UserID string `gorm:"index;not null" json:"-"`
    Name string `gorm:"not null" json:"name"`
    EncryptionPublicKey []byte `gorm:"not null" json:"encryption_public_key"`
    SigningPublicKey []byte `gorm:"not null" json:"signing_public_key"`
    CreatedAt time.Time `json:"created_at"`
    VerifiedAt *time.Time `json:"verified_at,omitempty"`
    TrustedAt *time.Time `json:"trusted_at,omitempty"`
    RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
