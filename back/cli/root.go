package cli

import (
 "errors"
 "fmt"
 "net/http"
 "time"
 "strings"
 "github.com/google/uuid"
 "github.com/pavlith/zzz/back/api"
 "github.com/pavlith/zzz/back/auth"
 "github.com/pavlith/zzz/back/models"
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
 var email string
 user:=&cobra.Command{Use:"user",Short:"Development identity provisioning"}
 create:=&cobra.Command{Use:"create",Short:"Create a development user and print a one-time API token",RunE:func(cmd *cobra.Command,args []string)error{
  if !strings.Contains(email,"@"){return fmt.Errorf("valid --email required")}
  c,err:=config.Load(configPath);if err!=nil{return err}
  db,err:=database.Open(c.Database.DSN);if err!=nil{return err}
  if err:=database.Migrate(db);err!=nil{return err}
  u:=models.User{ID:uuid.NewString(),Email:email}
  if err:=db.Create(&u).Error;err!=nil{return err}
  token,err:=auth.Issue(db,u.ID,24*time.Hour);if err!=nil{return err}
  fmt.Fprintf(cmd.OutOrStdout(),"user_id=%s\\ntoken=%s\\n",u.ID,token)
  return nil
 }}
 create.Flags().StringVar(&email,"email","","User email")
 user.AddCommand(create);root.AddCommand(user)
 root.AddCommand(&cobra.Command{Use:"serve",Short:"Start authenticated development HTTP API",RunE:func(cmd *cobra.Command,args []string)error{
  c,err:=config.Load(configPath);if err!=nil{return err}
  db,err:=database.Open(c.Database.DSN);if err!=nil{return err}
  if err:=database.Migrate(db);err!=nil{return err}
  server:=&http.Server{Addr:c.Server.Address,Handler:api.New(db),ReadHeaderTimeout:5*time.Second,ReadTimeout:15*time.Second,WriteTimeout:15*time.Second,IdleTimeout:60*time.Second}
  err=server.ListenAndServe()
  if errors.Is(err,http.ErrServerClosed){return nil}
  return err
 }})
 return root.Execute()
}
