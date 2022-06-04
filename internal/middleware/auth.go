package middleware

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func AuthCheck(as *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("auth check middleware triggered")

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Warn(token)

		c.Next()
	}
}
