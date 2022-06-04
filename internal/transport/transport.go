package transport

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/protos/auth"
)

type AuthenticationServer struct {
	auth.UnimplementedAuthenticationServer
	s *service.Service
}

func NewAuthenticationServer(s *service.Service) *AuthenticationServer {
	return &AuthenticationServer{
		s: s,
	}
}

func (as *AuthenticationServer) GetNextSynPackage(ctx context.Context, req *auth.SynPackage) (*auth.SynPackage, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context done")
	default:
	}

	next, err := as.s.NextSyn(uint(req.Id), req.Contents)
	if err != nil {
		return nil, err
	}

	return &auth.SynPackage{Id: req.Id, Contents: next}, nil
}
