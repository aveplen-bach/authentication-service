package service

import "github.com/aveplen-bach/authentication-service/internal/util"

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
	pld, err := util.ExPld(token)
	if err != nil {
		return err
	}

	ls.ss.Destroy(uint(pld.UserID))
	return nil
}
