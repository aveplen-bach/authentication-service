package middleware

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func EndToEndEncryption(ts *service.TokenService, ss *service.SessionService) gin.HandlerFunc {
	logrus.Info("end to end enctyption middleware registered")

	return func(c *gin.Context) {
		logrus.Info("end to end enctyption middleware triggered")

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			logrus.Warn(err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		payload, err := ts.ExtractPayload(token)
		if err != nil {
			logrus.Warn(err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		session, err := ss.Get(uint(payload.UserID))
		if err != nil {
			logrus.Warn(err)
			c.JSON(http.StatusNotFound, gin.H{
				"err": "you are not logged in or token is damaged",
			})
			return
		}

		if c.Request.Method == "GET" || c.Request.Method == "" {
			logrus.Info("skipping body decripton due to get request")
		} else {
			decryptReqBody(c, session)
		}

		bw := &bodyWriter{body: new(bytes.Buffer), ResponseWriter: c.Writer}
		c.Writer = bw

		c.Next()

		encryptResBody(c, session, bw)
	}
}

func decryptReqBody(c *gin.Context, session *model.SessionEntry) {
	logrus.Info("decyrpting request body")

	b64EncReqBody, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logrus.Warn(err)
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"err": err.Error(),
		})
		return
	}
	defer c.Request.Body.Close()

	encReqBody, err := base64.StdEncoding.DecodeString(string(b64EncReqBody))
	if err != nil {
		logrus.Warn(err)
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"err": err.Error(),
		})
		return
	}

	reqBody, err := cryptoutil.DecryptAesCbc(encReqBody, session.SessionKey, session.IV)
	if err != nil {
		logrus.Warn(err)
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"err": err.Error(),
		})
		return
	}

	c.Request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))
}

type bodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyWriter) Write(b []byte) (int, error) {
	logrus.Info("piping body write into ")
	return w.body.Write(b)
}

func encryptResBody(c *gin.Context, session *model.SessionEntry, bw *bodyWriter) {
	logrus.Info("encyrpting response body")

	decResBody, err := ioutil.ReadAll(bw.body)
	if err != nil {
		logrus.Warn(err)
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"err": err.Error(),
		})
		return
	}

	resBody, err := cryptoutil.EncryptAesCbc(decResBody, session.SessionKey, session.IV)
	if err != nil {
		logrus.Warn(err)
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"err": err.Error(),
		})
		return
	}

	b64ResBody := []byte(base64.StdEncoding.EncodeToString(resBody))

	c.Writer = bw.ResponseWriter
	c.Writer.Write(b64ResBody)
}
