package api

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "github.com/labstack/echo/v4"
 "github.com/labstack/echo/v4/middleware"
 "strings"
 
 "github.com/pavlith/zzz/back/acl"
 apimiddleware "github.com/pavlith/zzz/back/api/middleware"
 "github.com/pavlith/zzz/back/models"
 "github.com/pavlith/zzz/back/service"
 "gorm.io/gorm"
)

type API struct { db *gorm.DB; svc *service.Service }
func New(db *gorm.DB) http.Handler {
 a:=&API{db:db,svc:service.New(db)}
 e:=echo.New()
 e.HideBanner=true
 e.HidePort=true
 e.Use(middleware.Recover())
 e.Use(middleware.BodyLimit("1M"))
 e.Use(middleware.Secure())
 limiter:=newAuthLimiter()
 e.POST("/api/v1/auth/device/challenge",func(c echo.Context)error{limiter.wrap(a.sessionChallenge)(c.Response(),c.Request());return nil})
 e.POST("/api/v1/auth/device/session",func(c echo.Context)error{limiter.wrap(a.createDeviceSession)(c.Response(),c.Request());return nil})
 e.GET("/healthz",func(c echo.Context)error{
  return c.JSON(http.StatusOK,map[string]string{"status":"ok"})
 })
 v1:=e.Group("/api/v1")
 v1.Use(apimiddleware.RequireBearer(a.db))
 register:=func(method,path string,h handler){
  wrapped:=func(c echo.Context)error{
   r:=c.Request()
   for _,key:=range []string{"workspace","group","vault","item","device","session"} {
    if val:=c.Param(key);val!="" {r.SetPathValue(key,val)}
   }
   id:=c.Get(apimiddleware.UserIDKey).(string)
   h(c.Response(),r,id)
   return nil
  }
  v1.Add(method,path,wrapped)
 }
 register(http.MethodGet,"/me",a.me)
 register(http.MethodGet,"/sessions",a.listSessions)
 register(http.MethodDelete,"/sessions/:session",a.revokeSession)
 register(http.MethodGet,"/devices",a.listDevices)
 register(http.MethodGet,"/devices/audit",a.deviceAudit)
 register(http.MethodPost,"/devices",a.createDevice)
 register(http.MethodDelete,"/devices/:device",a.revokeDevice)
 register(http.MethodPost,"/devices/:device/challenge",a.issueDeviceChallenge)
 register(http.MethodPost,"/devices/:device/verify",a.verifyDevice)
 register(http.MethodPost,"/devices/:device/approval-challenge",a.approvalChallenge)
 register(http.MethodPost,"/devices/:device/approve",a.approveDevice)
 register(http.MethodGet,"/workspaces",a.workspaces)
 register(http.MethodPost,"/workspaces",a.workspaces)
 register(http.MethodPost,"/workspaces/:workspace/groups",a.groups)
 register(http.MethodPost,"/groups/:group/members",a.groupMembers)
 register(http.MethodPost,"/workspaces/:workspace/vaults",a.vaults)
 register(http.MethodPost,"/vaults/:vault/permissions",a.permissions)
 register(http.MethodGet,"/vaults/:vault/rotation-readiness",a.rotationReadiness)
 register(http.MethodPost,"/vaults/:vault/rotation/prepare",a.prepareRotation)
 register(http.MethodPost,"/vaults/:vault/rotation/sign",a.signRotation)
 register(http.MethodPost,"/vaults/:vault/rotation/envelope-ack",a.acknowledgeRotationEnvelope)
 register(http.MethodPost,"/vaults/:vault/rotation/history-ack",a.acknowledgeRotationHistory)
 register(http.MethodPost,"/vaults/:vault/rotation/commitment",a.submitRotationCommitment)
 register(http.MethodGet,"/vaults/:vault/rotation/commitments",a.rotationCommitmentViewEndpoint)
 register(http.MethodGet,"/vaults/:vault/rotation/transparency",a.rotationTransparencyLog)
 register(http.MethodGet,"/vaults/:vault/rotation",a.rotationStatus)
 register(http.MethodGet,"/vaults/:vault/rotation/preflight",a.rotationPreflightEndpoint)
 register(http.MethodPost,"/vaults/:vault/rotation/cancel",a.cancelRotation)
 register(http.MethodPost,"/vaults/:vault/rotation/activate",a.activateRotation)
 register(http.MethodGet,"/vaults/:vault/key-envelopes",a.listKeyEnvelopes)
 register(http.MethodGet,"/vaults/:vault/key-envelopes/history",a.historicalKeyEnvelopes)
 register(http.MethodPost,"/vaults/:vault/key-envelopes/history/rewrap",a.rewrapHistoricalEnvelope)
 register(http.MethodPost,"/vaults/:vault/key-envelopes",a.createKeyEnvelope)
 register(http.MethodGet,"/vaults/:vault/snapshot",a.snapshot)
 register(http.MethodGet,"/vaults/:vault/snapshot-consistent",a.consistentSnapshot)
 register(http.MethodGet,"/vaults/:vault/sync",a.pullSync)
 register(http.MethodPost,"/vaults/:vault/sync/push",a.pushSync)
 register(http.MethodGet,"/vaults/:vault/items",a.items)
 register(http.MethodPost,"/vaults/:vault/items",a.items)
 register(http.MethodGet,"/vaults/:vault/items/:item/revisions",a.itemRevisions)
 register(http.MethodGet,"/vaults/:vault/items/:item",a.singleItem)
 register(http.MethodPut,"/vaults/:vault/items/:item",a.singleItem)
 return e
}
type handler func(http.ResponseWriter,*http.Request,string)
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
 var in struct{Nonce []byte `json:"nonce"`;Ciphertext []byte `json:"ciphertext"`;CryptoVersion uint32 `json:"crypto_version"`;KeyEpoch uint64 `json:"key_epoch"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 if in.KeyEpoch==0{problem(w,400,"key_epoch_required");return}
 item:=models.Item{VaultID:vault,Nonce:in.Nonce,Ciphertext:in.Ciphertext,CryptoVersion:in.CryptoVersion}
 if err:=a.writeItemAtEpoch(id,&item,0,in.KeyEpoch);err!=nil{if errors.Is(err,errItemKeyEpoch){problem(w,409,"key_epoch_mismatch");return};failure(w,err);return}
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
 var in struct{ExpectedRevision uint64 `json:"expected_revision"`;Nonce []byte `json:"nonce"`;Ciphertext []byte `json:"ciphertext"`;CryptoVersion uint32 `json:"crypto_version"`;KeyEpoch uint64 `json:"key_epoch"`}
 if err:=decode(r,&in);err!=nil{problem(w,400,"invalid_json");return}
 if in.KeyEpoch==0{problem(w,400,"key_epoch_required");return}
 if in.ExpectedRevision==0{problem(w,400,"expected_revision_required");return}
 item:=models.Item{ID:itemID,VaultID:vault,Nonce:in.Nonce,Ciphertext:in.Ciphertext,CryptoVersion:in.CryptoVersion}
 if err:=a.writeItemAtEpoch(id,&item,in.ExpectedRevision,in.KeyEpoch);err!=nil{if errors.Is(err,errItemKeyEpoch){problem(w,409,"key_epoch_mismatch");return};failure(w,err);return}
 write(w,200,map[string]uint64{"revision":item.Revision})
}
