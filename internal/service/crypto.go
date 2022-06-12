package service

import (
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
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
	session, err := cs.ss.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}
	return cryptoutil.EncryptAesCbc(opentext, session.Key, session.IV)
}

func (cs *CryptoService) Decrypt(userID uint, ciphertext []byte) ([]byte, error) {
	session, err := cs.ss.Get(userID)
	if err != nil {
		return nil, fmt.Errorf("could not get session: %w", err)
	}
	return cryptoutil.DecryptAesCbc(ciphertext, session.Key, session.IV)
}
