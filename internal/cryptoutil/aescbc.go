package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/sirupsen/logrus"
)

func EncryptAesCbc(plaintext, key, iv []byte) ([]byte, error) {
	logrus.Info("encrypting aes cbc")
	padded, err := addPadding(plaintext, aes.BlockSize)
	if err != nil {
		logrus.Errorf("cannot add padding: %w", err)
		return nil, fmt.Errorf("cannot add padding: %w", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		logrus.Errorf("cannot create cipher: %w", err)
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	cbc := cipher.NewCBCEncrypter(c, iv)

	out := make([]byte, len(padded))
	cbc.CryptBlocks(out, padded)

	return out, nil
}

func DecryptAesCbc(ciphertext, key, iv []byte) ([]byte, error) {
	logrus.Info("decrypting aes cbc")
	c, err := aes.NewCipher(key)
	if err != nil {
		logrus.Errorf("cannot create cipher: %w", err)
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}

	cbc := cipher.NewCBCDecrypter(c, iv)

	out := make([]byte, len(ciphertext))
	cbc.CryptBlocks(out, ciphertext)

	unpadded, err := removePadding(out, aes.BlockSize)
	if err != nil {
		logrus.Errorf("cannot remove padding: %w", err)
		return nil, fmt.Errorf("cannot remove padding: %w", err)
	}

	return unpadded, nil
}

func addPadding(plaintext []byte, blockSize int) ([]byte, error) {
	logrus.Info("adding padding")
	if blockSize <= 0 {
		logrus.Errorf("invalid block size")
		return nil, fmt.Errorf("invalid block size")
	}
	if len(plaintext) == 0 {
		return []byte{}, nil
	}

	padding := byte(blockSize - len(plaintext)%blockSize)

	out := make([]byte, len(plaintext)+int(padding))
	copy(out, plaintext)

	for i := 0; i < int(padding); i++ {
		out[len(out)-1-i] = padding
	}

	return out, nil
}

func removePadding(ciphertext []byte, blockSize int) ([]byte, error) {
	logrus.Info("removing padding")
	if blockSize <= 0 {
		logrus.Errorf("invalid block size")
		return nil, fmt.Errorf("invalid block size")
	}
	if len(ciphertext) == 0 {
		return []byte{}, nil
	}
	if len(ciphertext)%blockSize != 0 {
		logrus.Errorf("invalid data")
		return nil, fmt.Errorf("invalid data")
	}

	c := ciphertext[len(ciphertext)-1]
	n := int(c)
	if n == 0 || n > len(ciphertext) {
		logrus.Errorf("invalid data")
		return nil, fmt.Errorf("invalid PKCS7 data")
	}
	for i := 0; i < n; i++ {
		if ciphertext[len(ciphertext)-n+i] != c {
			logrus.Errorf("invalid data")
			return nil, fmt.Errorf("invalid PKCS7 data")
		}
	}
	return ciphertext[:len(ciphertext)-n], nil
}
