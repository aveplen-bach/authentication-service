package controller

import (
	"fmt"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func RegisterUser(rs *service.RegisterService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("register endpoint called")
		req := &model.RegisterRequest{}
		if err := c.BindJSON(req); err != nil {
			logrus.Info("could not respond to register: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		if err := rs.Register(req); err != nil {
			logrus.Info("could not respond to register: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info("register success")
		c.JSON(http.StatusOK, gin.H{
			"info": fmt.Sprintf("user %s registered successfully", req.Username),
		})
	}
}
