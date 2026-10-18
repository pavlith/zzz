package api

import (
 "net/http/httptest"
 "testing"

 "github.com/pavlith/zzz/back/database"
)

func TestDeviceChallengeRequiresAuth(t *testing.T) {
 db, err := database.Open(":memory:")
 if err != nil { t.Fatal(err) }
 if err := database.Migrate(db); err != nil { t.Fatal(err) }
 server := New(db)
 for _, path := range []string{"/api/v1/devices/a/challenge", "/api/v1/devices/a/verify"} {
  req := httptest.NewRequest("POST", path, nil)
  rec := httptest.NewRecorder()
  server.ServeHTTP(rec, req)
  if rec.Code != 401 { t.Fatalf("%s: expected 401, got %d", path, rec.Code) }
 }
}
