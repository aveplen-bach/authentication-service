package middleware

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/util"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func EndToEndEncryption(session *service.SessionService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// decrypt request body

		logrus.Info("decrypting request body")

		protToken, err := util.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		s, err := session.Get(uint(protToken.Payload.UserID))
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

		reqBody, err := cryptoutil.DecryptAesCbc(encReqBody, s.SessionKey, s.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))

		logrus.Info("passing decrypted body to handler")

		// pass to real handler
		c.Next()

		logrus.Info("encrypting response body")

		// encrypt resposne body
		decResBody, err := ioutil.ReadAll(c.Request.Response.Body)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		resBody, err := cryptoutil.EncryptAesCbc(decResBody, s.SessionKey, s.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Response.Body = ioutil.NopCloser(bytes.NewReader(resBody))
	}
}
