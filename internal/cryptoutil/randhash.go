package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/sirupsen/logrus"
)

func GenerateRandomString(len int) (string, error) {
	logrus.Info("generating random string")
	randomBytes := make([]byte, len)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(randomBytes), nil
}
