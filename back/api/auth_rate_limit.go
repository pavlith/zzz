package api

import (
 "net"
 "net/http"
 "sync"
 "time"
)

// authLimiter is a bounded, process-local limiter. Deployments with multiple
// replicas must replace this with a shared limiter at the trusted edge.
type authLimiter struct {
 mu sync.Mutex
 entries map[string]authBucket
}
type authBucket struct {
 Started time.Time
 Count int
}
func newAuthLimiter()*authLimiter{return &authLimiter{entries:make(map[string]authBucket)}}
func(l *authLimiter) allow(key string,now time.Time)bool{
 l.mu.Lock()
 defer l.mu.Unlock()
 if len(l.entries)>4096{
  for k,v:=range l.entries{if now.Sub(v.Started)>=time.Minute{delete(l.entries,k)}}
  if len(l.entries)>4096{return false}
 }
 v:=l.entries[key]
 if v.Started.IsZero()||now.Sub(v.Started)>=time.Minute{v=authBucket{Started:now}}
 if v.Count>=10{return false}
 v.Count++
 l.entries[key]=v
 return true
}
func(l *authLimiter) wrap(next http.HandlerFunc)http.HandlerFunc{
 return func(w http.ResponseWriter,r *http.Request){
  ip,_,err:=net.SplitHostPort(r.RemoteAddr)
  if err!=nil{ip=r.RemoteAddr}
  if ip==""{ip="unknown"}
  if !l.allow(ip,time.Now().UTC()){
   w.Header().Set("Retry-After","60")
   problem(w,http.StatusTooManyRequests,"rate_limited")
   return
  }
  next(w,r)
 }
}
