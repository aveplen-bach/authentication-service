package service

import (
	"sync"
)

type SessionEntry struct {
	MessageAuthCode string
	SessionKey      []byte
	UserID          int
	UserIDSet       bool
}

type SessionService struct {
	store map[int]*SessionEntry
	cnt   int
	mu    *sync.Mutex
}

func NewSessionService() *SessionService {
	return &SessionService{
		store: make(map[int]*SessionEntry),
		cnt:   0,
		mu:    &sync.Mutex{},
	}
}

func (s *SessionService) Get(sessionID int) (*SessionEntry, bool) {
	entry, ok := s.store[sessionID]
	return entry, ok
}

func (s *SessionService) Add(entry *SessionEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cnt++
	s.store[s.cnt] = entry
	return s.cnt
}
