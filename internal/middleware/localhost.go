package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Localhost() gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("localhost middleware")

		if !strings.Contains(c.Request.RemoteAddr, "127.0.0.1") {
			logrus.Warn("local endpoint accessed from remote addres")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"err": "localhsot only",
			})
			return
		}

		c.Next()
	}
}
