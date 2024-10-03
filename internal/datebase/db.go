package database

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

type DB struct {
	Conn *sql.DB
}

func NewDB() (*DB, error) {
	dsn := "root:ComplexPassw0rd!@tcp(127.0.0.1:3307)/domain_checker"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	// Проверка подключения
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &DB{Conn: db}, nil
}
