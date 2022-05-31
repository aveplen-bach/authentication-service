package middleware

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

const BEARER_SCHEMA = "Bearer "

func Authenticated(t *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		tokenString := authHeader[len(BEARER_SCHEMA):]

		valid, err := t.ValidateToken(tokenString)
		if err != nil {
			panic(err)
		}

		if !valid {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}
