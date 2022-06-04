package controller

import (
	"fmt"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func RegisterUser(rs *service.RegisterService) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &model.RegisterRequest{}
		if err := c.BindJSON(req); err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		err := rs.Register(req)

		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"info": fmt.Sprintf("user <%s> registered successfully", req.Username),
		})
	}
}
