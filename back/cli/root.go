package cli

import (
 "errors"
 "fmt"
 "net/http"
 "github.com/spf13/cobra"
 "github.com/pavlith/zzz/back/config"
 "github.com/pavlith/zzz/back/database"
)

func Execute() error {
 var configPath string
 root:=&cobra.Command{Use:"zzz",Short:"Encrypted vault backend",SilenceUsage:true}
 root.PersistentFlags().StringVarP(&configPath,"config","c","","YAML config path")
 root.AddCommand(&cobra.Command{Use:"migrate",Short:"Initialize SQLite schema",RunE:func(cmd *cobra.Command,args []string)error{
  c,err:=config.Load(configPath);if err!=nil{return err}
  db,err:=database.Open(c.Database.DSN);if err!=nil{return err}
  return database.Migrate(db)
 }})
 root.AddCommand(&cobra.Command{Use:"serve",Short:"Start health-only HTTP server (no authentication API yet)",RunE:func(cmd *cobra.Command,args []string)error{
  c,err:=config.Load(configPath);if err!=nil{return err}
  db,err:=database.Open(c.Database.DSN);if err!=nil{return err}
  if err:=database.Migrate(db);err!=nil{return err}
  mux:=http.NewServeMux()
  mux.HandleFunc("GET /healthz",func(w http.ResponseWriter,r *http.Request){w.WriteHeader(http.StatusOK);fmt.Fprintln(w,"ok")})
  server:=&http.Server{Addr:c.Server.Address,Handler:mux,ReadHeaderTimeout:5_000_000_000}
  err=server.ListenAndServe()
  if errors.Is(err,http.ErrServerClosed){return nil}
  return err
 }})
 return root.Execute()
}
