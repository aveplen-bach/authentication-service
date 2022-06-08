package service

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
	pld, err := ls.ts.ExtractPayload(token)
	if err != nil {
		return err
	}

	ls.ss.Destroy(uint(pld.UserID))
	return nil
}
