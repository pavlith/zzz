package api

import (
 "net/http/httptest"
 "testing"
 "time"

 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/database"
 "github.com/pavlith/zzz/back/models"
)

func TestSessionInventoryAndRevoke(t *testing.T){
 db,err:=database.Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=database.Migrate(db);err!=nil{t.Fatal(err)}
 for _,u:=range []models.User{{ID:"a",Email:"a@invalid.test"},{ID:"b",Email:"b@invalid.test"}}{
  if err:=db.Create(&u).Error;err!=nil{t.Fatal(err)}
 }
 first,err:=auth.Issue(db,"a",time.Hour);if err!=nil{t.Fatal(err)}
 second,err:=auth.Issue(db,"a",time.Hour);if err!=nil{t.Fatal(err)}
 other,err:=auth.Issue(db,"b",time.Hour);if err!=nil{t.Fatal(err)}
 var token auth.Token
 if err:=db.Where("hash = ?",auth.Hash(second)).First(&token).Error;err!=nil{t.Fatal(err)}
 server:=New(db)
 call:=func(method,path,bearer string)*httptest.ResponseRecorder{
  req:=httptest.NewRequest(method,path,nil);req.Header.Set("Authorization","Bearer "+bearer)
  res:=httptest.NewRecorder();server.ServeHTTP(res,req);return res
 }
 if got:=call("GET","/api/v1/sessions",first).Code;got!=200{t.Fatalf("list status %d",got)}
 if got:=call("DELETE","/api/v1/sessions/"+token.ID,other).Code;got!=404{t.Fatalf("cross-account revoke status %d",got)}
 if got:=call("DELETE","/api/v1/sessions/"+token.ID,first).Code;got!=200{t.Fatalf("revoke status %d",got)}
 if got:=call("GET","/api/v1/me",second).Code;got!=401{t.Fatalf("revoked token still valid %d",got)}
 if got:=call("GET","/api/v1/me",first).Code;got!=200{t.Fatalf("unrelated token affected %d",got)}
}
