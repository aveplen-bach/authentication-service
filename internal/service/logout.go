package service

import (
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/util"
	"github.com/sirupsen/logrus"
)

type LogoutService struct {
	ts *TokenService
	ss *SessionService
}

func NewLogoutService(ts *TokenService, ss *SessionService) *LogoutService {
	return &LogoutService{
		ss: ss,
		ts: ts,
	}
}

func (ls *LogoutService) Logout(token string) error {
	logrus.Info("handling logout")
	pld, err := util.ExPld(token)
	if err != nil {
		logrus.Errorf("could not extract payload: %w", err)
		return fmt.Errorf("could not extract payload: %w", err)
	}

	ls.ss.Destroy(uint(pld.UserID))
	return nil
}
