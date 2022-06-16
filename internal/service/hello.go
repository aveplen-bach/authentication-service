package service

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/aveplen-bach/authentication-service/internal/cryptoutil"
	"github.com/sirupsen/logrus"
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
	logrus.Info("generating hello session context")
	now := uint(time.Now().Unix())

	session, err := h.ss.New(now)
	if err != nil {
		logrus.Errorf("could not get create session: %w", err)
		return HelloCridentials{}, fmt.Errorf("could not get create session: %w", err)
	}

	session.Key = pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 16, sha1.New)
	randIV, err := cryptoutil.GenerateRandomString(16)
	if err != nil {
		logrus.Error("could not generate random string")
		return HelloCridentials{}, fmt.Errorf("could not generate random string: %w", err)
	}
	session.IV, err = base64.StdEncoding.DecodeString(randIV)
	if err != nil {
		logrus.Error("could not decode random iv")
		return HelloCridentials{}, fmt.Errorf("could not decode random string: %w", err)
	}

	token, err := h.ts.Construct(now, true)
	if err != nil {
		logrus.Errorf("could not generate token: %w", err)
		return HelloCridentials{}, fmt.Errorf("could not generate token: %w", err)
	}

	return HelloCridentials{
		Token: token,
		Key:   base64.StdEncoding.EncodeToString(session.Key),
		IV:    base64.StdEncoding.EncodeToString(session.IV),
	}, nil
}
