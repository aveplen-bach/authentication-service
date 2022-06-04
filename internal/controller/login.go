package controller

import (
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
)

func LoginUser(ls *service.LoginService) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &model.LoginRequest{}
		c.BindJSON(req)

		res, err := ls.Login(req)

		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
		}

		c.JSON(http.StatusOK, res)
	}
}
