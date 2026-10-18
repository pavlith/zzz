package api

import (
 "bytes"
 "encoding/base64"
 "fmt"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestDeviceOwnership(t *testing.T) {
 db, err := database.Open(":memory:")
 if err != nil { t.Fatal(err) }
 if err := database.Migrate(db); err != nil { t.Fatal(err) }
 for _, u := range []models.User{
  {ID:"alice",Email:"alice@invalid.test"}, {ID:"bob",Email:"bob@invalid.test"},
 } {
  if err := db.Create(&u).Error; err != nil { t.Fatal(err) }
 }
 alice, err := auth.Issue(db,"alice",time.Hour); if err != nil { t.Fatal(err) }
 bob, err := auth.Issue(db,"bob",time.Hour); if err != nil { t.Fatal(err) }
 router := New(db)
 request := func(method,path,body,token string) *httptest.ResponseRecorder {
  req := httptest.NewRequest(method,path,bytes.NewBufferString(body))
  if token != "" { req.Header.Set("Authorization","Bearer "+token) }
  req.Header.Set("Content-Type","application/json")
  w := httptest.NewRecorder()
  router.ServeHTTP(w,req)
  return w
 }
 key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1},32))
 payload := fmt.Sprintf(`{"name":"laptop","encryption_public_key":"%s","signing_public_key":"%s"}`,key,key)
 if got:=request("POST","/api/v1/devices",payload,"").Code;got!=401 { t.Fatalf("anonymous: %d",got) }
 if got:=request("POST","/api/v1/devices",payload,alice).Code;got!=201 { t.Fatalf("create: %d",got) }
 var d models.Device
 if err:=db.Where("user_id = ?","alice").First(&d).Error;err!=nil {t.Fatal(err)}
 if got:=request("DELETE","/api/v1/devices/"+d.ID,"",bob).Code;got!=404 {t.Fatalf("cross-user revoke: %d",got)}
 if got:=request("DELETE","/api/v1/devices/"+d.ID,"",alice).Code;got!=200 {t.Fatalf("own revoke: %d",got)}
}
