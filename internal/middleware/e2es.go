package middleware

import (
	"bytes"
	"encoding/base64"
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

		b64EncReqBody, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}
		defer c.Request.Body.Close()

		encReqBody, err := base64.StdEncoding.DecodeString(string(b64EncReqBody))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		reqBody, err := cryptoutil.DecryptAesCbc(encReqBody, session.SessionKey, session.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))

		bw := &bodyWriter{body: new(bytes.Buffer), ResponseWriter: c.Writer}
		c.Writer = bw

		// pass to real handler
		c.Next()

		// encrypt resposne body
		decResBody, err := ioutil.ReadAll(bw.body)
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

		b64ResBody := []byte(base64.StdEncoding.EncodeToString(resBody))

		c.Writer = bw.ResponseWriter
		c.Writer.Write(b64ResBody)
	}
}

type bodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}
