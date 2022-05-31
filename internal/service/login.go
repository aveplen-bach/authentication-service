package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"golang.org/x/crypto/pbkdf2"
)

const (
	STAGE_CLIENT_CONN_INIT = iota + 1
	STAGE_SERVER_GEN_MAC
	STAGE_CLIENT_CRIDENTIALS
	STAGE_SERVER_TOKEN
)

func (s *Service) Login(req *model.LoginRequest) (*model.LoginResponse, error) {
	switch req.Stage {
	case STAGE_CLIENT_CONN_INIT:
		return s.handleConnectionInit(req)

	case STAGE_CLIENT_CRIDENTIALS:
		return s.handleCredentials(req)

	default:
		return nil, errors.New("unknown stage")
	}
}

// client conn init stage

func (s *Service) handleConnectionInit(loginRequest *model.LoginRequest) (*model.LoginResponse, error) {
	mac, err := s.generateSessionMAC(loginRequest)
	if err != nil {
		return nil, err
	}

	sessionID := s.Session.Add(&SessionEntry{
		MessageAuthCode: mac,
	})

	return &model.LoginResponse{
		SessionID: sessionID,
		MAC:       mac,
		Stage:     STAGE_SERVER_GEN_MAC,
	}, nil
}

func (s *Service) generateSessionMAC(_ *model.LoginRequest) (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil
	}

	return base64.StdEncoding.EncodeToString(randomBytes), nil
}

// client cridentials stage

func (s *Service) handleCredentials(request *model.LoginRequest) (*model.LoginResponse, error) {
	var user model.User
	if result := s.Db.Where("username = ?", request.Username).First(&user); result.Error != nil {
		return nil, result.Error
	}

	session, ok := s.Session.Get(request.SessionID)
	if !ok {
		return nil, errors.New("session does not exist")
	}

	skey, err := s.deriveSessionKey([]byte(user.Password), session.MessageAuthCode)
	if err != nil {
		return nil, err
	}

	session.SessionKey = skey

	photo, err := s.decryptPhoto(skey, request.EncryptedPhoto, request.IV)
	if err != nil {
		return nil, err
	}

	if photoOk, err := s.CheckPhoto(DeserializeFloats64(user.FFVector), photo); !photoOk || err != nil {
		if err != nil {
			return nil, err
		}
		if !photoOk {
			return nil, errors.New("photo is not ok")
		}
	}

	token, err := s.Token.GenerateToken(&user)
	if err != nil {
		return nil, err
	}

	return &model.LoginResponse{
		Stage: STAGE_SERVER_TOKEN,
		JWT:   token,
	}, nil
}

func (s *Service) deriveSessionKey(password []byte, sessionMAC string) ([]byte, error) {
	sessionMACBytes, err := base64.StdEncoding.DecodeString(sessionMAC)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key(password, sessionMACBytes, 4096, 16, sha1.New)

	return key, nil
}

func (s *Service) decryptPhoto(key []byte, encryptedPhoto, iv string) ([]byte, error) {
	encPhoto, err := base64.StdEncoding.DecodeString(encryptedPhoto)
	if err != nil {
		return nil, err
	}

	ivDecoded, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return nil, err
	}

	cipherText := new(bytes.Buffer)
	cipherText.Write(encPhoto)

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(c, ivDecoded)
	plainText := make([]byte, len(cipherText.Bytes()))
	cbc.CryptBlocks(plainText, cipherText.Bytes())

	unpadded, err := pkcs7Unpad(plainText, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unpadded, nil
}

func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("ErrInvalidBlockSize")
	}
	if len(b) == 0 {
		return nil, errors.New("ErrInvalidPKCS7Data")
	}
	if len(b)%blocksize != 0 {
		return nil, errors.New("ErrInvalidPKCS7Padding")
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errors.New("ErrInvalidPKCS7Padding")
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errors.New("ErrInvalidPKCS7Padding")
		}
	}
	return b[:len(b)-n], nil
}
