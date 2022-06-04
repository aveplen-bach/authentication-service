package middleware

import (
	"fmt"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func IncrementalToken(ts *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		next, err := ts.NextToken(token)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Next()

		c.Header("Authorizatoin", fmt.Sprintf("Bearer %s", next))
	}
}
