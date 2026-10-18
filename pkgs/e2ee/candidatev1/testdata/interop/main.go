package main

import (
 "crypto/ed25519"
 "crypto/ecdh"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "io"
 "os"

 candidate "github.com/pavlith/zzz/pkgs/e2ee/candidatev1"
)

type input struct {
 Envelope candidate.Envelope `json:"envelope"`
 RecipientPrivateKey string `json:"recipient_private_key"`
 SignerPublicKey string `json:"signer_public_key"`
 VaultKey string `json:"vault_key"`
}
func decode(value string, length int) ([]byte,error) {
 b,err:=base64.RawURLEncoding.DecodeString(value)
 if err!=nil||len(b)!=length||base64.RawURLEncoding.EncodeToString(b)!=value {
  return nil,fmt.Errorf("invalid test key encoding")
 }
 return b,nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
func run()error{
 data,err:=io.ReadAll(io.LimitReader(os.Stdin,64*1024));if err!=nil{return err}
 var in input
 if err=json.Unmarshal(data,&in);err!=nil{return err}
 recipientBytes,err:=decode(in.RecipientPrivateKey,32);if err!=nil{return err}
 signerBytes,err:=decode(in.SignerPublicKey,32);if err!=nil{return err}
 expected,err:=decode(in.VaultKey,32);if err!=nil{return err}
 recipient,err:=ecdh.X25519().NewPrivateKey(recipientBytes);if err!=nil{return err}
 _=recipient
 manifest,err:=decode(in.Envelope.ManifestSHA256,32);if err!=nil{return err}
 var hash [32]byte;copy(hash[:],manifest)
 context:=candidate.Context{
  VaultID:in.Envelope.VaultID,DeviceID:in.Envelope.DeviceID,
  RotationID:in.Envelope.RotationID,SignerDeviceID:in.Envelope.SignerDeviceID,
  KeyEpoch:in.Envelope.KeyEpoch,ManifestSHA256:hash,
 }
 plain,err:=candidate.Unwrap(in.Envelope,recipientBytes,ed25519.PublicKey(signerBytes),context)
 if err!=nil{return err}
 if len(plain)!=len(expected){return fmt.Errorf("wrong plaintext length")}
 for i:=range plain{if plain[i]!=expected[i]{return fmt.Errorf("wrong plaintext")}}
 fmt.Println("Go verified browser envelope")
 return nil
}
