package cryptoutil

import "fmt"

func AddPadding(plaintext []byte, blockSize int) ([]byte, error) {
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

func RemovePadding(ciphertext []byte, blockSize int) ([]byte, error) {
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
