package transport

import (
	"context"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/protos/auth"
)

type AuthenticationServer struct {
	auth.UnimplementedAuthenticationServer
	ts *service.TokenService
	cs *service.CryptoService
}

func NewAuthenticationServer(ts *service.TokenService, cs *service.CryptoService) *AuthenticationServer {
	return &AuthenticationServer{
		ts: ts,
		cs: cs,
	}
}

func (as *AuthenticationServer) GetNextSynPackage(ctx context.Context, req *auth.SynPackage) (*auth.SynPackage, error) {
	next, err := as.ts.NextSyn(uint(req.Id), req.Contents)
	if err != nil {
		return nil, err
	}

	return &auth.SynPackage{Id: req.Id, Contents: next}, nil
}

func (as *AuthenticationServer) Decrypt(ctx context.Context, req *auth.Ciphertext) (*auth.Opentext, error) {
	opentext, err := as.cs.Decrypt(uint(req.Id), req.Contents)
	if err != nil {
		return nil, err
	}

	return &auth.Opentext{Id: req.Id, Contents: opentext}, nil
}

func (as *AuthenticationServer) Encrypt(ctx context.Context, req *auth.Opentext) (*auth.Ciphertext, error) {
	ciphertext, err := as.cs.Encrypt(uint(req.Id), req.Contents)
	if err != nil {
		return nil, err
	}

	return &auth.Ciphertext{Id: req.Id, Contents: ciphertext}, nil
}
