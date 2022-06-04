package controller

import (
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func RegisterUser(rs *service.RegisterService) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.SetCookie("jwt_token", "hello, I'm jwt-token", 3600, "/", "localhost", false, true)
	}
}
