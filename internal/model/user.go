package model

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string
	Password string
	FFVector string
	Admin    bool
}

type UserDto struct {
	UserID    uint      `json:"userId"`
	Username  string    `json:"username"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updateddAt"`
}
