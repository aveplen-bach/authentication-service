package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UserController struct {
	Db *gorm.DB
}

func (u *UserController) Get(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "http://localhost:8080")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")

	var users []gin.H = []gin.H{
		{
			"id":       1,
			"username": "username1",
			"vector":   "vector1",
		},
		{
			"id":       2,
			"username": "username2",
			"vector":   "vector2",
		},
		{
			"id":       3,
			"username": "username3",
			"vector":   "vector3",
		},
		{
			"id":       4,
			"username": "username4",
			"vector":   "vector4",
		},
	}

	// u.db.Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}
