package middleware

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/ginutil"
	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func IncrementalToken(ts *service.TokenService) gin.HandlerFunc {
	logrus.Info("incremental token middleware registered")

	return func(c *gin.Context) {
		logrus.Info("incremental token middleware triggered")

		token, err := ginutil.ExtractToken(c)
		if err != nil {
			logrus.Warn(err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		next, err := ts.NextToken(token)
		if err != nil {
			logrus.Warn(err)
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		bw := &bodyWriter{body: new(bytes.Buffer), ResponseWriter: c.Writer}
		c.Writer = bw

		c.Next()

		resb, err := ioutil.ReadAll(bw.body)
		if err != nil {
			logrus.Fatal(err)
		}

		// я хочу умереть, глядя на этот код, но чтобы сделать переписать его красиво,
		// нужно время, которого у меня нет)))
		var newresb []byte
		if len(resb) == 0 {
			newresb, err = json.Marshal(gin.H{
				"next": next,
			})
		} else {
			var unmr interface{}
			if err = json.Unmarshal(resb, &unmr); err != nil {
				newresb, err = json.Marshal(gin.H{
					"next": next,
					"data": string(resb),
				})
			} else {
				newresb, err = json.Marshal(gin.H{
					"next": next,
					"data": unmr.(map[string]interface{}),
				})
			}
		}

		if err != nil {
			logrus.Fatal(err)
		}

		c.Writer = bw.ResponseWriter
		c.Writer.Write(newresb)
	}
}
