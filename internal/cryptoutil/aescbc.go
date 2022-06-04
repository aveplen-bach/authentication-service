package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func EncryptAesCbc(plaintext, key, iv []byte) ([]byte, error) {
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

func DecryptAesCbc(ciphertext, key, iv []byte) ([]byte, error) {
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

	padding := byte(blockSize - len(plaintext)%blockSize)

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
