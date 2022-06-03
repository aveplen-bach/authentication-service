package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

type UserController struct {
	service *service.Service
}

func NewUserController(service *service.Service) *UserController {
	return &UserController{
		service: service,
	}
}

func (u *UserController) ListUsers(c *gin.Context) {
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
