package service

import (
	"sync"

	"github.com/aveplen-bach/authentication-service/internal/model"
)

type SessionService struct {
	store map[int]*model.SessionEntry
	cnt   int
	mu    *sync.Mutex
}

func NewSessionService() *SessionService {
	return &SessionService{
		store: make(map[int]*model.SessionEntry),
		cnt:   0,
		mu:    &sync.Mutex{},
	}
}

func (s *SessionService) Get(sessionID int) (*model.SessionEntry, bool) {
	entry, ok := s.store[sessionID]
	return entry, ok
}

func (s *SessionService) Add(entry *model.SessionEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cnt++
	s.store[s.cnt] = entry
	return s.cnt
}
