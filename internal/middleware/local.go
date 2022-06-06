package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Localhost() gin.HandlerFunc {
	logrus.Info("localhost middleware registered")
	return func(c *gin.Context) {
		logrus.Info("localhost middleware triggered")

		ip := c.GetHeader("X-Real-Ip")
		if ip == "" {
			ip = c.GetHeader("X-Forwarded-For")
		}
		if ip == "" {
			ip = strings.Split(c.Request.RemoteAddr, ":")[0]
		}

		myip, _ := findMyIP()
		if !(ip == myip || ip == "127.0.0.1") {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"err": "localhost only",
			})
			return
		}

		c.Next()
	}
}

func findMyIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	var ret string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ret = ipnet.IP.String()
			}
		}
	}

	return ret, nil
}
