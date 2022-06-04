package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func ListUsers(us *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {

		users, err := us.GetAllUsers()
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"info":  "users fetched successfully",
			"users": users,
		})
	}
}
