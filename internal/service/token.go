package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
)

type TokenService struct {
}

func NewTokenService() *TokenService {
	return &TokenService{}
}

func (t *TokenService) GenerateToken(userID uint) (string, error) {
	synchronization, _ := t.constructSynchronization()
	header, _ := t.constructHeader()
	payload, _ := t.constructPayload(userID)
	signature, _ := t.constructSignature(header, payload)

	return fmt.Sprintf(
		"%s.%s.%s.%s",
		synchronization,
		header,
		payload,
		signature,
	), nil
}

// Deprecated ... это syn, тут шифрование должно быть
func (t *TokenService) constructSynchronization() (string, error) {
	syn := model.Synchronization{
		Syn: 1,
		Inc: 1,
	}

	b, err := json.Marshal(syn)
	if err != nil {
		return "", err
	}

	b64Syn := base64.StdEncoding.EncodeToString(b)
	return b64Syn, nil
}

func (t *TokenService) constructHeader() (string, error) {
	head := model.Header{
		SignatureAlg:  "HMACSHA256",
		EncryptionAlg: "AESCBC",
	}

	b, err := json.Marshal(head)
	if err != nil {
		return "", nil
	}

	b64Head := base64.StdEncoding.EncodeToString(b)
	return b64Head, nil
}

func (t *TokenService) constructPayload(userID uint) (string, error) {
	payload := model.Payload{
		UserID: int(userID),
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	b64Payload := base64.StdEncoding.EncodeToString(b)
	return b64Payload, nil
}

func (t *TokenService) constructSignature(header, payload string) (string, error) {
	secret := "mysecret"
	data := fmt.Sprintf("%s.%s", header, payload)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	sha := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return sha, nil
}

func (t *TokenService) ValidateToken(token string) (bool, error) {
	return true, nil
}
