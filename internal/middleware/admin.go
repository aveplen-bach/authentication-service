package middleware

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Admin() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := ginutil.ExtractToken(c)
		if err != nil {
			logrus.Errorf("could not extract token: %w", err)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"err": err.Error(),
			})
			return
		}

		payload, err := util.ExPld(token)
		if err != nil {
			logrus.Errorf("could not extract payload from token: %w", err)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"err": err.Error(),
			})
			return
		}

		if !payload.Admin {
			logrus.Warn("admin endpoint accessed by common user")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"err": "admin only",
			})
			return
		}

		c.Next()
	}
}
