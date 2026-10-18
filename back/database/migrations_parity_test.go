package database

import (
 "sort"
 "testing"

 "gorm.io/gorm"
)

type schemaColumn struct{
 Name string
 Type string
 Notnull int
 PK int
}

// Inspect field shape independent of sqlite_master DDL serialization.
func tableColumns(db *gorm.DB,table string)([]schemaColumn,error){
 rows,err:=db.Raw("PRAGMA table_info("+table+")").Rows()
 if err!=nil{return nil,err}
 defer rows.Close()
 var out []schemaColumn
 for rows.Next(){
  var col schemaColumn
  var cid int
  var defaultValue any
  if err:=rows.Scan(&cid,&col.Name,&col.Type,&col.Notnull,&defaultValue,&col.PK);err!=nil{return nil,err}
  out=append(out,col)
 }
 sort.Slice(out,func(i,j int)bool{return out[i].Name<out[j].Name})
 return out,rows.Err()
}

func TestSQLBaselineParityWithLegacyGORM(t *testing.T){
 old,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 modern,err:=Open(":memory:");if err!=nil{t.Fatal(err)}
 if err:=baselineSchema(old);err!=nil{t.Fatal(err)}
 if err:=Migrate(modern);err!=nil{t.Fatal(err)}
 var legacyTables []string
 if err:=old.Raw("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").Scan(&legacyTables).Error;err!=nil{t.Fatal(err)}
 for _,name:=range legacyTables{
  want,err:=tableColumns(old,name);if err!=nil{t.Fatal(err)}
  got,err:=tableColumns(modern,name);if err!=nil{t.Fatal(err)}
  if len(want)!=len(got){t.Errorf("%s: expected %d columns, got %d",name,len(want),len(got));continue}
  for i:=range want{
   if want[i].Name!=got[i].Name||want[i].PK!=got[i].PK{
    t.Errorf("%s column %d: legacy %+v != SQL %+v",name,i,want[i],got[i])
   }
  }
 }
}
