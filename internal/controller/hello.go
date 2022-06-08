package controller

import (
	"net/http"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func Hello(hs *service.HelloService) gin.HandlerFunc {
	return func(c *gin.Context) {
		now := uint(time.Now().Unix())

		hello, err := hs.Hello(now)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, hello)
	}
}
