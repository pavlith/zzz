package config

import (
 "fmt"
 "strings"
 "github.com/spf13/viper"
)

type Config struct {
 Server struct { Address string `mapstructure:"address"` } `mapstructure:"server"`
 Database struct { DSN string `mapstructure:"dsn"` } `mapstructure:"database"`
}
func Load(path string) (Config,error) {
 v:=viper.New()
 v.SetConfigType("yaml")
 if path!="" { v.SetConfigFile(path) } else { v.SetConfigName("config"); v.AddConfigPath(".") }
 v.SetEnvPrefix("ZZZ")
 v.SetEnvKeyReplacer(strings.NewReplacer(".","_"))
 v.AutomaticEnv()
 v.SetDefault("server.address","127.0.0.1:8080")
 v.SetDefault("database.dsn","data/zzz.sqlite")
 if err:=v.ReadInConfig();err!=nil {
  if _,ok:=err.(viper.ConfigFileNotFoundError);!ok { return Config{},fmt.Errorf("config read: %w",err) }
 }
 var c Config
 if err:=v.Unmarshal(&c);err!=nil{return c,err}
 if c.Server.Address==""||c.Database.DSN=="" {return c,fmt.Errorf("server.address and database.dsn are required")}
 return c,nil
}
