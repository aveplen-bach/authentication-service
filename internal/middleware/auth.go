package middleware

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Authenticated(t *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := util.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info(token)

		c.Next()
	}
}
