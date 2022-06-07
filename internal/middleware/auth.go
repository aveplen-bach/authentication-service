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
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		valid, err := as.IsAuthenticated(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		if !valid {
			logrus.Warn("token %s not valid", token)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": "token is not valid",
			})
			return
		}

		c.Next()
	}
}
