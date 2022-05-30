package controller

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func Index(c *gin.Context) {
	cookie, err := c.Cookie("jwt_token")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Cookie value: %s\n", cookie)
}
