package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/sirupsen/logrus"
)

type TokenService struct {
	ss *SessionService
}

func NewTokenService() *TokenService {
	return &TokenService{}
}

func (t *TokenService) GenerateToken(userID uint) (string, error) {
	return t.constructToken(userID)
}

func (t *TokenService) NextToken(token string) (string, error) {
	deconstructed, err := t.deconstructToken(token)
	if err != nil {
		return "", fmt.Errorf("could not deconstruct token: %w", err)
	}

	deconstructed.Synchronization.Syn += deconstructed.Synchronization.Inc

	reconstructed, err := t.constructToken(uint(deconstructed.Payload.UserID))
	if err != nil {
		return "", fmt.Errorf("could not reconstruct token: %w", err)
	}

	return reconstructed, nil
}

func (t *TokenService) ValidateToken(token string) (bool, error) {
	deconstructed, err := t.deconstructToken(token)
	if err != nil {
		return false, fmt.Errorf("could not deconstruct token: %w", err)
	}

	logrus.Warn("Validate token not implemented", deconstructed)

	return true, nil
}

func (t *TokenService) ExtractPayload(token string) (model.Payload, error) {
	deconstructed, err := t.deconstructToken(token)
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not deconstruct token: %w", err)
	}

	return deconstructed.Payload, nil
}

func (t *TokenService) constructToken(userID uint) (string, error) {
	synchronization, err := t.constructSynchronization(userID)
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	header, err := t.constructHeader(userID)
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	payload, err := t.constructPayload(userID)
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	signature, err := t.constructSignature(header, payload)
	if err != nil {
		return "", fmt.Errorf("could not construct token: %w", err)
	}

	return fmt.Sprintf(
		"%s.%s.%s.%s",
		synchronization,
		header,
		payload,
		signature,
	), nil
}

func (t *TokenService) constructSynchronization(userID uint) (string, error) {
	session, err := t.ss.Get(userID)
	if err != nil {
		return "", fmt.Errorf("could not get user session: %w", err)
	}

	syn := model.Synchronization{
		Syn: 1,
		Inc: 1,
	}

	b, err := json.Marshal(syn)
	if err != nil {
		return "", err
	}

	encSyn, err := cryptoutil.EncryptAesCbc(b, session.SessionKey, session.IV)
	if err != nil {
		return "", fmt.Errorf("could not encrypt syn part of the token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encSyn), nil
}

func (t *TokenService) constructHeader(userID uint) (string, error) {
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

func (t *TokenService) deconstructToken(token string) (model.TokenRaw, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 4 {
		return model.TokenRaw{}, fmt.Errorf("token is damaged or of wrong format")
	}

	head, err := t.deconstructHeader(tokenParts[1])
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not deconstruct header: %w", err)
	}

	payload, err := t.deconstructPayload(tokenParts[2])
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not deconstruct payload: %w", err)
	}

	syn, err := t.deconstructSynchronization(uint(payload.UserID), tokenParts[0])
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not deconstruct syn: %w", err)
	}

	sign, err := t.deconstructSignature(tokenParts[3])
	if err != nil {
		return model.TokenRaw{}, fmt.Errorf("could not deconstruct signature: %w", err)
	}

	return model.TokenRaw{
		Synchronization: syn,
		Header:          head,
		Payload:         payload,
		SignatureBytes:  sign,
	}, nil
}

func (t *TokenService) deconstructSynchronization(userID uint, synStr string) (model.Synchronization, error) {
	synBytes, err := base64.StdEncoding.DecodeString(synStr)
	if err != nil {
		return model.Synchronization{}, fmt.Errorf("could not decode syn: %w", err)
	}

	session, err := t.ss.Get(userID)
	if err != nil {
		return model.Synchronization{}, fmt.Errorf("could not get user session: %w", err)
	}

	b, err := cryptoutil.DecryptAesCbc(synBytes, session.SessionKey, session.IV)
	if err != nil {
		return model.Synchronization{}, fmt.Errorf("could not decrypt syn: %w", err)
	}

	var syn model.Synchronization
	if err := json.Unmarshal(b, &syn); err != nil {
		return model.Synchronization{}, fmt.Errorf("could not unmarshal syn: %w", err)
	}

	return syn, nil
}

func (t *TokenService) deconstructHeader(headerStr string) (model.Header, error) {
	headBytes, err := base64.StdEncoding.DecodeString(headerStr)
	if err != nil {
		return model.Header{}, fmt.Errorf("could not decode header: %w", err)
	}

	var head model.Header
	if err := json.Unmarshal(headBytes, &head); err != nil {
		return model.Header{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	return head, nil
}

func (t *TokenService) deconstructPayload(payloadStr string) (model.Payload, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(payloadStr)
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not decode payload: %w", err)
	}

	var payload model.Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return model.Payload{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	return payload, nil
}

func (t *TokenService) deconstructSignature(signatureStr string) ([]byte, error) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureStr)
	if err != nil {
		return nil, fmt.Errorf("could not decode signature: %w", err)
	}
	return signatureBytes, nil
}
