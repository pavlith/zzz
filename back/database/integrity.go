package database

import (
 "fmt"

 "gorm.io/gorm"
)

// checkSQLiteIntegrity stops migrations on damaged pages or FK violations.
// Integrity checks cannot replace a verified offline backup/restore procedure.
func checkSQLiteIntegrity(db *gorm.DB)error{
 var result string
 if err:=db.Raw("PRAGMA integrity_check").Scan(&result).Error;err!=nil{return fmt.Errorf("sqlite integrity check: %w",err)}
 if result!="ok"{return fmt.Errorf("sqlite integrity check failed: %s",result)}
 rows,err:=db.Raw("PRAGMA foreign_key_check").Rows()
 if err!=nil{return fmt.Errorf("sqlite foreign keys: %w",err)}
 defer rows.Close()
 if rows.Next(){return fmt.Errorf("sqlite foreign key violations detected")}
 return rows.Err()
}
