package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ListUsers(us *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("user endpoint called")
		users, err := us.GetAllUsers()
		if err != nil {
			logrus.Warnf("could not respond to user: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		logrus.Info("user success")
		c.JSON(http.StatusOK, gin.H{
			"info":  "users fetched successfully",
			"users": users,
		})
	}
}
