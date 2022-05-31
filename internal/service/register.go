package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
)

// TODO: переделать сессии на доступ по userID
func (s *Service) Register(userID uint, request *model.RegisterRequest) error {
	session, ok := s.Session.Get(int(userID))
	if !ok {
		return fmt.Errorf("session not initialized for %d", userID)
	}

	reqPayload, err := s.decryptRegisterPayload(session.SessionKey, request.EncryptedPayload)
	if err != nil {
		return err
	}

	photo, err := base64.StdEncoding.DecodeString(reqPayload.Photo)
	if err != nil {
		return err
	}

	objectID, err := s.upload(photo)
	if err != nil {
		return err
	}

	f64Vecotr, err := s.extractVector(objectID)
	if err != nil {
		return err
	}

	user := model.User{
		Username: reqPayload.Username,
		Password: reqPayload.Password,
		FFVector: SerializeFloats64(f64Vecotr),
	}

	result := s.Db.Save(&user)

	return result.Error
}

func (s *Service) decryptRegisterPayload(key []byte, encryptedPayload string) (*model.RegisterRequestPayload, error) {
	encPayloadBytes, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return nil, err
	}

	cipherText := new(bytes.Buffer)
	cipherText.Write(encPayloadBytes)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := encPayloadBytes[c.BlockSize():]

	cbc := cipher.NewCBCDecrypter(c, iv)
	plainText := make([]byte, len(cipherText.Bytes()))
	cbc.CryptBlocks(plainText, cipherText.Bytes())

	unpadded, err := pkcs7Unpad(plainText, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	var reqPayload model.RegisterRequestPayload
	if err := json.Unmarshal(unpadded, &reqPayload); err != nil {
		return nil, err
	}

	return &reqPayload, nil
}
