package api

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "strings"
 
 "github.com/pavlith/zzz/back/acl"
 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/service"
 "gorm.io/gorm"
)

type API struct { db *gorm.DB; svc *service.Service }
func New(db *gorm.DB)http.Handler{
 a:=&API{db:db,svc:service.New(db)}
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){write(w,200,map[string]string{"status":"ok"})})
 mux.HandleFunc("GET /api/v1/me",a.secure(a.me))
 mux.HandleFunc("GET /api/v1/workspaces",a.secure(a.workspaces))
 mux.HandleFunc("POST /api/v1/workspaces",a.secure(a.workspaces))
 mux.HandleFunc("POST /api/v1/workspaces/{workspace}/groups",a.secure(a.groups))
 mux.HandleFunc("POST /api/v1/groups/{group}/members",a.secure(a.groupMembers))
 mux.HandleFunc("POST /api/v1/workspaces/{workspace}/vaults",a.secure(a.vaults))
 mux.HandleFunc("POST /api/v1/vaults/{vault}/permissions",a.secure(a.permissions))
 mux.HandleFunc("GET /api/v1/vaults/{vault}/items",a.secure(a.items))
 mux.HandleFunc("POST /api/v1/vaults/{vault}/items",a.secure(a.items))
 mux.HandleFunc("GET /api/v1/vaults/{vault}/items/{item}",a.secure(a.singleItem))
 mux.HandleFunc("PUT /api/v1/vaults/{vault}/items/{item}",a.secure(a.singleItem))
 return http.MaxBytesHandler(mux,1<<20)
}
type handler func(http.ResponseWriter,*http.Request,string)
func (a *API)secure(h handler)http.HandlerFunc{
 return func(w http.ResponseWriter,r *http.Request){
  id,err:=auth.Authenticate(a.db,r.Header.Get("Authorization"))
  if err!=nil {problem(w,401,"unauthorized");return}
  h(w,r,id)
 }
}
func decode(r *http.Request,v any)error{
 d:=json.NewDecoder(io.LimitReader(r.Body,1<<20));d.DisallowUnknownFields()
 if err:=d.Decode(v);err!=nil{return err}
 var extra any
 if err:=d.Decode(&extra);err!=io.EOF{return errors.New("request must contain one JSON object")}
 return nil
}
func write(w http.ResponseWriter,status int,v any){
 w.Header().Set("Content-Type","application/json")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(status);_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter,status int,code string){write(w,status,map[string]string{"error":code})}
func failure(w http.ResponseWriter,err error){
 if errors.Is(err,acl.ErrForbidden)||errors.Is(err,gorm.ErrRecordNotFound){problem(w,404,"not_found");return}
 if strings.Contains(err.Error(),"revision conflict"){problem(w,409,"revision_conflict");return}
 problem(w,400,"invalid_request")
}
func (a *API)me(w http.ResponseWriter,r *http.Request,id string){
 var u models.User
 if err:=a.db.First(&u,"id = ?",id).Error;err!=nil{failure(w,err);return}
 write(w,200,map[string]string{"id":u.ID,"email":u.Email,"display_name":u.DisplayName})
}
func (a *API)workspaces(w http.ResponseWriter,r *http.Request,id string){
 if r.Method=="GET"{
  var out []models.Workspace
  err:=a.db.Model(&models.Workspace{}).Joins("JOIN workspace_members m ON m.workspace_id = workspaces.id").Where("m.user_id = ?",id).Find(&out).Error
  if err!=nil{failure(w,err);return};write(w,200,out);return
 }
 var in struct{Name string `json:"name"`;Kind string `json:"kind"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 if in.Kind!="personal"&&in.Kind!="team"{problem(w,400,"invalid_kind");return}
 out,err:=a.svc.CreateWorkspace(id,in.Name,in.Kind);if err!=nil{failure(w,err);return}
 write(w,201,out)
}
func (a *API)groups(w http.ResponseWriter,r *http.Request,id string){
 var in struct{Name string `json:"name"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 g,err:=a.svc.CreateGroup(id,r.PathValue("workspace"),in.Name)
 if err!=nil{failure(w,err);return};write(w,201,g)
}
func (a *API)groupMembers(w http.ResponseWriter,r *http.Request,id string){
 var in struct{UserID string `json:"user_id"`}
 if err:=decode(r,&in);err!=nil||in.UserID==""{problem(w,400,"invalid_json");return}
 if err:=a.svc.AddGroupMember(id,r.PathValue("group"),in.UserID);err!=nil{failure(w,err);return}
 write(w,200,map[string]bool{"ok":true})
}
func (a *API)vaults(w http.ResponseWriter,r *http.Request,id string){
 var in struct{Name string `json:"name"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 v,err:=a.svc.CreateVault(id,r.PathValue("workspace"),in.Name)
 if err!=nil{failure(w,err);return};write(w,201,v)
}
func (a *API)permissions(w http.ResponseWriter,r *http.Request,id string){
 var in struct{PrincipalType string `json:"principal_type"`;PrincipalID string `json:"principal_id"`;Read bool `json:"read"`;Write bool `json:"write"`;Manage bool `json:"manage"`}
 if err:=decode(r,&in);err!=nil||in.PrincipalID==""{problem(w,400,"invalid_json");return}
 p:=models.VaultPermission{VaultID:r.PathValue("vault"),PrincipalType:in.PrincipalType,PrincipalID:in.PrincipalID,CanRead:in.Read,CanWrite:in.Write,CanManage:in.Manage}
 if err:=a.svc.Grant(id,p);err!=nil{failure(w,err);return}
 write(w,201,map[string]bool{"ok":true})
}
func (a *API)check(w http.ResponseWriter,id,vault string,action acl.Action)bool{
 yes,err:=acl.Allowed(a.db,id,vault,action)
 if err!=nil||!yes{problem(w,404,"not_found");return false};return true
}
func (a *API)items(w http.ResponseWriter,r *http.Request,id string){
 vault:=r.PathValue("vault")
 if r.Method=="GET"{
  if !a.check(w,id,vault,acl.Read){return}
  var rows []models.Item
  if err:=a.db.Where("vault_id = ? AND deleted_at IS NULL",vault).Order("created_at, id").Limit(500).Find(&rows).Error;err!=nil{failure(w,err);return}
  write(w,200,rows);return
 }
 if !a.check(w,id,vault,acl.Write){return}
 var in struct{Nonce []byte `json:"nonce"`;Ciphertext []byte `json:"ciphertext"`;CryptoVersion uint32 `json:"crypto_version"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 item:=models.Item{VaultID:vault,Nonce:in.Nonce,Ciphertext:in.Ciphertext,CryptoVersion:in.CryptoVersion}
 if err:=a.svc.PutItem(id,&item,0);err!=nil{failure(w,err);return}
 write(w,201,item)
}
func (a *API)singleItem(w http.ResponseWriter,r *http.Request,id string){
 vault:=r.PathValue("vault"); itemID:=r.PathValue("item")
 if r.Method=="GET"{
  if !a.check(w,id,vault,acl.Read){return}
  var item models.Item
  if err:=a.db.First(&item,"id = ? AND vault_id = ? AND deleted_at IS NULL",itemID,vault).Error;err!=nil{failure(w,err);return}
  write(w,200,item);return
 }
 if !a.check(w,id,vault,acl.Write){return}
 var in struct{ExpectedRevision uint64 `json:"expected_revision"`;Nonce []byte `json:"nonce"`;Ciphertext []byte `json:"ciphertext"`;CryptoVersion uint32 `json:"crypto_version"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 if in.ExpectedRevision==0{problem(w,400,"expected_revision_required");return}
 item:=models.Item{ID:itemID,VaultID:vault,Nonce:in.Nonce,Ciphertext:in.Ciphertext,CryptoVersion:in.CryptoVersion}
 if err:=a.svc.PutItem(id,&item,in.ExpectedRevision);err!=nil{failure(w,err);return}
 write(w,200,map[string]uint64{"revision":item.Revision})
}
