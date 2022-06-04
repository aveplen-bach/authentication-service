package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func Authentication(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
	})
}
