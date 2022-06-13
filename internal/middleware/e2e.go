package middleware

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/sirupsen/logrus"

	"github.com/gin-gonic/gin"
)

func EndToEndEncryption(cs *service.CryptoService) gin.HandlerFunc {
	return func(c *gin.Context) {
		logrus.Info("end to end enctyption middleware triggered")

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			logrus.Errorf("could not extract token: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		payload, err := util.ExPld(token)
		if err != nil {
			logrus.Errorf("could not extract payload from token: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		if c.Request.Method == "GET" || c.Request.Method == "" {
			logrus.Info("skipping body decripton due to get request")
		} else {
			logrus.Info("decyrpting request body")

			b64EncReqBody, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				logrus.Errorf("could not read request body: %w", err)
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
					"err": err.Error(),
				})
				return
			}
			defer c.Request.Body.Close()

			encReqBody, err := base64.StdEncoding.DecodeString(string(b64EncReqBody))
			if err != nil {
				logrus.Errorf("could not decode request body: %w", err)
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
					"err": err.Error(),
				})
				return
			}

			reqBody, err := cs.Decrypt(uint(payload.UserID), encReqBody)
			if err != nil {
				logrus.Errorf("could not decrypt request body: %w", err)
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
					"err": err.Error(),
				})
				return
			}

			c.Request.Body = ioutil.NopCloser(bytes.NewReader(reqBody))
		}

		bw := &bodyWriter{body: new(bytes.Buffer), ResponseWriter: c.Writer}
		c.Writer = bw

		c.Next()

		logrus.Info("encyrpting response body")

		decResBody, err := ioutil.ReadAll(bw.body)
		if err != nil {
			logrus.Errorf("could not read response body: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		resBody, err := cs.Encrypt(uint(payload.UserID), decResBody)
		if err != nil {
			logrus.Errorf("could not encrypt response body: %w", err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
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
	logrus.Info("piping body write into buffer")
	return w.body.Write(b)
}
