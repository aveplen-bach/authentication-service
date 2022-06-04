package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func EncryptAesCbc(plaintext, key, iv []byte) ([]byte, error) {
	padded, err := AddPadding(plaintext, aes.BlockSize)
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

	unpadded, err := RemovePadding(out, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}
