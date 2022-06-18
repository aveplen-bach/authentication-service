package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Login(ls *service.LoginService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("login endpoint called")
		req := &model.LoginRequest{}
		if err := c.BindJSON(req); err != nil {
			logrus.Errorf("could not response to login: %w", err)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"err": err.Error(),
			})
			return
		}

		login, err := ls.Login(req)

		if err != nil {
			logrus.Errorf("could not response to login: %w", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info("responding to login")
		c.JSON(http.StatusOK, login)
	}
}
