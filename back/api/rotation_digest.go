package api

import (
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "hash"

 "github.com/pavlith/zzz/back/models"
)

func digestField(h hash.Hash,s string){
 var length [8]byte
 binary.BigEndian.PutUint64(length[:],uint64(len(s)))
 _,_=h.Write(length[:])
 _,_=h.Write([]byte(s))
}

// manifestDigest requires callers to provide recipients sorted by device ID.
func manifestDigest(rotation models.VaultRotation,members []models.RotationRecipient)string{
 h:=sha256.New()
 digestField(h,"zzz-vault-recipient-manifest-v1")
 digestField(h,rotation.VaultID)
 digestField(h,rotation.ID)
 var version [8]byte
 binary.BigEndian.PutUint64(version[:],rotation.FromEpoch)
 _,_=h.Write(version[:])
 binary.BigEndian.PutUint64(version[:],rotation.ToEpoch)
 _,_=h.Write(version[:])
 binary.BigEndian.PutUint64(version[:],uint64(len(members)))
 _,_=h.Write(version[:])
 for _,m:=range members{
  digestField(h,m.DeviceID)
  digestField(h,m.UserID)
  digestField(h,m.SigningKeySHA256)
  digestField(h,m.EncryptionKeySHA256)
 }
 return hex.EncodeToString(h.Sum(nil))
}
