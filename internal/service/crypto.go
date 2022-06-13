package service

import (
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/sirupsen/logrus"
)

type CryptoService struct {
	ss *SessionService
}

func NewCryptoService(ss *SessionService) *CryptoService {
	return &CryptoService{
		ss: ss,
	}
}

func (cs *CryptoService) Encrypt(userID uint, opentext []byte) ([]byte, error) {
	logrus.Info("encrypting data")
	session, err := cs.ss.Get(userID)
	if err != nil {
		logrus.Errorf("could not get session: %w", err)
		return nil, fmt.Errorf("could not get session: %w", err)
	}
	return cryptoutil.EncryptAesCbc(opentext, session.Key, session.IV)
}

func (cs *CryptoService) Decrypt(userID uint, ciphertext []byte) ([]byte, error) {
	logrus.Info("decrypting data")
	session, err := cs.ss.Get(userID)
	if err != nil {
		logrus.Errorf("could not get session: %w", err)
		return nil, fmt.Errorf("could not get session: %w", err)
	}
	return cryptoutil.DecryptAesCbc(ciphertext, session.Key, session.IV)
}
