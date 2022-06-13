package ginutil

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ExtractToken(c *gin.Context) (string, error) {
	logrus.Info("extracting request token")

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		logrus.Errorf("authorization header is empty")
		return "", fmt.Errorf("authorization header is empty")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		logrus.Errorf("token bearer scheme violated")
		return "", fmt.Errorf("token bearer scheme violated")
	}

	if authHeaderParts[0] != "Bearer" {
		logrus.Errorf("token is not bearer")
		return "", fmt.Errorf("token is not bearer")
	}

	return authHeaderParts[1], nil
}
