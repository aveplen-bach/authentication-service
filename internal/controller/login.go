package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func LoginUser(ls *service.LoginService) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &model.LoginRequest{}
		if err := c.BindJSON(req); err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		login, err := ls.Login(req)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, login)
	}
}
