package controller

import (
	"net/http"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Hello(hs *service.HelloService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("hello endpoint called")
		now := uint(time.Now().Unix())

		hello, err := hs.Hello(now)
		if err != nil {
			logrus.Errorf("could not respond to hello: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info("responding to hello")
		c.JSON(http.StatusOK, hello)
	}
}
