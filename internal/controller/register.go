package controller

import (
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

type RegisterController struct {
	service *service.Service
}

func NewRegisterController(service *service.Service) *RegisterController {
	return &RegisterController{
		service: service,
	}
}

func (l *RegisterController) RegisterUser(c *gin.Context) {
	c.SetCookie("jwt_token", "hello, I'm jwt-token", 3600, "/", "localhost", false, true)
}
