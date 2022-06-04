package service

type AuthService struct {
	ts *TokenService
}

func NewAuthService(ts *TokenService) *AuthService {
	return &AuthService{
		ts: ts,
	}
}

func (as *AuthService) IsAuthenticated(token string) (bool, error) {
	return as.ts.ValidateToken(token)
}
