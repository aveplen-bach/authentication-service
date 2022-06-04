package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomString(len int) (string, error) {
	randomBytes := make([]byte, len)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(randomBytes), nil
}
