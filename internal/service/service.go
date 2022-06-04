package service

import "fmt"

type Service struct {
	ts *TokenService
}

func NewService(ts *TokenService) *Service {
	return &Service{
		ts: ts,
	}
}

func (s *Service) NextSyn(userID uint, syn []byte) ([]byte, error) {
	next, err := s.ts.NextSyn(userID, syn)
	if err != nil {
		return nil, fmt.Errorf("could not get next syn: %w", err)
	}

	return next, nil
}
