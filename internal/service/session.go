package service

import (
	"fmt"
	"sync"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/sirupsen/logrus"
)

type SessionService struct {
	store map[uint]*model.SessionEntry
	mu    *sync.Mutex
}

func NewSessionService() *SessionService {
	return &SessionService{
		store: make(map[uint]*model.SessionEntry),
		mu:    &sync.Mutex{},
	}
}

func (s *SessionService) Get(userID uint) (*model.SessionEntry, error) {
	logrus.Info("getting session")
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.store[userID]
	if !ok {
		logrus.Errorf("session for given user does not exist")
		return nil, fmt.Errorf("session for given user does not exist")
	}
	return entry, nil
}

func (s *SessionService) New(userID uint) (*model.SessionEntry, error) {
	logrus.Info("creating session")
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.store[userID]; ok {
		logrus.Errorf("session for given user already exists")
		return nil, fmt.Errorf("session for given user already exists")
	}

	newSessoinEntry := &model.SessionEntry{}
	s.store[userID] = newSessoinEntry

	return newSessoinEntry, nil
}

func (s *SessionService) Destroy(userID uint) {
	logrus.Info("destroing session")
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.store, userID)
}
