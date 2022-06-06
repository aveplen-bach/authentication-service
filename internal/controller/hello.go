package controller

import (
	"crypto/sha1"
	"encoding/base64"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/pbkdf2"
)

type HelloRequest struct {
	UserID int `json:"userId"`
}

func Hello(ss *service.SessionService, ts *service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req HelloRequest
		if err := c.BindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session, err := ss.New(uint(req.UserID))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session.SessionKey = pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 16, sha1.New)
		session.IV = make([]byte, 16)

		token, err := ts.GenerateToken(uint(req.UserID))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "successfully created token",
			"token":  token,
			"key":    base64.StdEncoding.EncodeToString(session.SessionKey),
			"iv":     base64.StdEncoding.EncodeToString(session.IV),
		})
	}
}
