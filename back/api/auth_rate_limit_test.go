package api

import (
 "net/http/httptest"
 "testing"
 "time"
)

func TestAnonymousAuthLimiter(t *testing.T){
 limiter:=newAuthLimiter()
 now:=time.Now().UTC()
 for i:=0;i<10;i++{
  if !limiter.allow("192.0.2.5",now){t.Fatalf("early rejection at %d",i)}
 }
 if limiter.allow("192.0.2.5",now){t.Fatal("limit not enforced")}
 if !limiter.allow("198.51.100.10",now){t.Fatal("unrelated IP blocked")}
 if !limiter.allow("192.0.2.5",now.Add(time.Minute)){t.Fatal("limit did not reset")}
}
func TestAnonymousAuthLimiterHTTP(t *testing.T){
 handler:=newAuthLimiter().wrap(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(204)})
 for i:=0;i<11;i++{
  r:=httptest.NewRequest("POST","/auth",nil)
  r.RemoteAddr="192.0.2.5:12345"
  w:=httptest.NewRecorder()
  handler(w,r)
  expected:=204
  if i==10{expected=429}
  if w.Code!=expected{t.Fatalf("attempt %d: status %d",i,w.Code)}
  if i==10&&w.Header().Get("Retry-After")!="60"{t.Fatal("missing Retry-After")}
 }
}
