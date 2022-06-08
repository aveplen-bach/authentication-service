package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func Logout(ls *service.LogoutService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		if err := ls.Logout(token); err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"info": "session destroyed successfully",
		})
	}
}
