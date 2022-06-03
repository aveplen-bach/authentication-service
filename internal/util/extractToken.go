package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func ExtractToken(c *gin.Context) (*model.TokenProtected, error) {
	logrus.Info("extracting request token")

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header is empty")
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 {
		return nil, fmt.Errorf("token bearer scheme violated")
	}

	if authHeaderParts[0] != "Bearer" {
		return nil, fmt.Errorf("token is not bearer")
	}

	tokenParts := strings.Split(authHeaderParts[1], ".")
	if len(tokenParts) != 4 {
		return nil, fmt.Errorf("token has wrong format")
	}

	synchronisationBytes, err := base64.StdEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, fmt.Errorf("cannot decode synchronisation part of the token: %w", err)
	}

	headerBytes, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("cannot decode header part of the token: %w", err)
	}
	var header model.Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("cannot unmarshal header part of the token: %w", err)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return nil, fmt.Errorf("cannot decode payload part of the token: %w", err)
	}
	var payload model.Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("cannot unmarshal payload part of the token: %w", err)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(tokenParts[3])
	if err != nil {
		return nil, fmt.Errorf("cannot decode signature part of the token: %w", err)
	}

	return &model.TokenProtected{
		SynchronizationBytes: synchronisationBytes,
		Header:               header,
		Payload:              payload,
		SignatureBytes:       signatureBytes,
	}, nil
}
