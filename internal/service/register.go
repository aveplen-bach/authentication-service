package service

import (
	"encoding/base64"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/util"
)

type RegisterService struct {
	us *UserService
	ps *PhotoService
}

func NewRegisterService(us *UserService, ps *PhotoService) *RegisterService {
	return &RegisterService{
		us: us,
		ps: ps,
	}
}

func (rs *RegisterService) Register(rreq *model.RegisterRequest) error {
	photoBytes, err := base64.StdEncoding.DecodeString(rreq.Photo)
	if err != nil {
		return fmt.Errorf("cannot decode photo: %w", err)
	}

	vector, err := rs.ps.ExtractVector(photoBytes)
	if err != nil {
		return fmt.Errorf("cannot extract ff vector: %w", err)
	}

	user := &model.User{
		Username: rreq.Username,
		Password: rreq.Password,
		FFVector: util.SerializeFloats64(vector),
		Admin:    rreq.Admin,
	}

	if err := rs.us.NewUser(user); err != nil {
		return fmt.Errorf("could not register user: %w", err)
	}

	return nil
}
