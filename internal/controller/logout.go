package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Logout(ls *service.LogoutService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("logout endpoint called")
		token, err := ginutil.ExtractToken(c)
		if err != nil {
			logrus.Warnf("could not respond to logout: %w", err)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"err": err.Error(),
			})
			return
		}

		if err := ls.Logout(token); err != nil {
			logrus.Warnf("could not respond to logout: %w", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info("logout success")
		c.JSON(http.StatusOK, gin.H{
			"info": "session destroyed successfully",
		})
	}
}
