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

func (l *LoginController) LoginUser(c *gin.Context) {
	req := &model.LoginRequest{}
	c.BindJSON(req)

	res, err := l.service.Login(req)

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
	}

	c.JSON(http.StatusOK, res)
}
