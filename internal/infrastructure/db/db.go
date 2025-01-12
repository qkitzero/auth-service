package db

import (
	"fmt"

	"github.com/qkitzero/auth/internal/infrastructure/persistence/user"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func Init(dbUser, dbPassword, dbHost, dbPort, dbName string) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(
		&user.UserTable{},
	); err != nil {
		return nil, err
	}

	return db, nil
}
