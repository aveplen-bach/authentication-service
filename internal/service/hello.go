package service

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type HelloService struct {
	ss *SessionService
	ts *TokenService
}

func NewHelloService(ss *SessionService, ts *TokenService) *HelloService {
	return &HelloService{
		ss: ss,
		ts: ts,
	}
}

type HelloCridentials struct {
	Token string `json:"token"`
	Key   string `json:"key"`
	IV    string `json:"iv"`
}

func (h *HelloService) Hello(userID uint) (HelloCridentials, error) {
	now := uint(time.Now().Unix())

	session, err := h.ss.New(now)
	if err != nil {
		return HelloCridentials{}, fmt.Errorf("could not get create session: %w", err)
	}

	session.SessionKey = pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 16, sha1.New)
	session.IV = make([]byte, 16)

	token, err := h.ts.GenerateAdminToken(now)
	if err != nil {
		return HelloCridentials{}, fmt.Errorf("could not generate token: %w", err)
	}

	return HelloCridentials{
		Token: token,
		Key:   base64.StdEncoding.EncodeToString(session.SessionKey),
		IV:    base64.StdEncoding.EncodeToString(session.IV),
	}, nil
}
