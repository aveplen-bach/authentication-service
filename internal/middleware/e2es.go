package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func EndToEndEncryption(service *service.Service) gin.HandlerFunc {
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

		s, ok := service.Session.Get(protToken.Payload.SessionID)
		if !ok {
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

		reqBody, err := decryptAesCbc(encReqBody, s.SessionKey, s.IV)
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

		resBody, err := encryptAesCbc(decResBody, s.SessionKey, s.IV)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"err": err.Error(),
			})
			return
		}

		c.Request.Response.Body = ioutil.NopCloser(bytes.NewReader(resBody))
	}
}

func encryptAesCbc(plaintext, key, iv []byte) ([]byte, error) {
	padded, err := addPadding(plaintext, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("cannot add padding: %w", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	cbc := cipher.NewCBCEncrypter(c, iv)

	out := make([]byte, len(padded))
	cbc.CryptBlocks(out, padded)

	return out, nil
}

func decryptAesCbc(ciphertext, key, iv []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	cbc := cipher.NewCBCDecrypter(c, iv)

	out := make([]byte, len(ciphertext))
	cbc.CryptBlocks(out, ciphertext)

	unpadded, err := removePadding(out, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

func addPadding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("invalid data")
	}

	padding := byte(len(plaintext) - len(plaintext)%blockSize)

	out := make([]byte, len(plaintext)+int(padding))
	copy(out, plaintext)

	for i := 0; i < int(padding); i++ {
		out[len(out)-1-i] = padding
	}

	return out, nil
}

func removePadding(ciphertext []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid block size")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("invalid data")
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("invalid data")
	}

	c := ciphertext[len(ciphertext)-1]
	n := int(c)
	if n == 0 || n > len(ciphertext) {
		return nil, fmt.Errorf("invalid PKCS7 data")
	}
	for i := 0; i < n; i++ {
		if ciphertext[len(ciphertext)-n+i] != c {
			return nil, fmt.Errorf("invalid PKCS7 data")
		}
	}
	return ciphertext[:len(ciphertext)-n], nil
}
