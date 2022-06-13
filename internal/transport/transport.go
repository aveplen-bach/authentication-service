package transport

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/service"
	"github.com/aveplen-bach/authentication-service/protos/auth"
	"github.com/sirupsen/logrus"
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
	logrus.Info("responding to get next syn package rpc")
	next, err := as.ts.NextSyn(uint(req.Id), req.Contents)
	if err != nil {
		logrus.Errorf("could not get next syn package: %w", err)
		return nil, fmt.Errorf("could not get next syn package: %w", err)
	}

	return &auth.SynPackage{Id: req.Id, Contents: next}, nil
}

func (as *AuthenticationServer) Decrypt(ctx context.Context, req *auth.Ciphertext) (*auth.Opentext, error) {
	logrus.Info("responding to decrypt rpc")
	opentext, err := as.cs.Decrypt(uint(req.Id), req.Contents)
	if err != nil {
		logrus.Errorf("could not decrypt data: %w", err)
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	return &auth.Opentext{Id: req.Id, Contents: opentext}, nil
}

func (as *AuthenticationServer) Encrypt(ctx context.Context, req *auth.Opentext) (*auth.Ciphertext, error) {
	logrus.Info("responding to encrypt rpc")
	ciphertext, err := as.cs.Encrypt(uint(req.Id), req.Contents)
	if err != nil {
		logrus.Errorf("could not encrypt data: %w", err)
		return nil, fmt.Errorf("could not encrypt data: %w", err)
	}

	return &auth.Ciphertext{Id: req.Id, Contents: ciphertext}, nil
}
