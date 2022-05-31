package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

type LoginController struct {
	service *service.Service
}

func NewLoginController(service *service.Service) *LoginController {
	return &LoginController{
		service: service,
	}
}

func (l *LoginController) Post(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "http://localhost:8080")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE")

	req := &model.LoginRequest{}
	c.BindJSON(req)

	res, err := l.service.Login(req)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}

	c.JSON(http.StatusOK, res)
}
