package middleware

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func EndToEndEncryption(ts *service.TokenService, ss *service.SessionService) gin.HandlerFunc {
	logrus.Info("auth check middleware registered")

	return func(c *gin.Context) {
		logrus.Info("auth check middleware triggered")

		// decrypt request body

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		payload, err := ts.ExtractPayload(token)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session, err := ss.Get(uint(payload.UserID))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": "you are not logged in or token is damaged",
			})
			return
		}

		encReqBody, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}
		defer c.Request.Body.Close()

		reqBody, err := cryptoutil.DecryptAesCbc(encReqBody, session.SessionKey, session.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))

		// pass to real handler
		c.Next()

		// encrypt resposne body
		decResBody, err := ioutil.ReadAll(c.Request.Response.Body)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		resBody, err := cryptoutil.EncryptAesCbc(decResBody, session.SessionKey, session.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Response.Body = ioutil.NopCloser(bytes.NewReader(resBody))
	}
}
