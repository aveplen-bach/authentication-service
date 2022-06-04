package service

import (
	"encoding/base64"
	"fmt"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/aveplen-bach/authentication-service/internal/util"
	"gorm.io/gorm"
)

type RegisterService struct {
	db *gorm.DB
	ps *PhotoService
}

func NewRegisterService(db *gorm.DB, ps *PhotoService) *RegisterService {
	return &RegisterService{
		db: db,
		ps: ps,
	}
}

func (rs *RegisterService) Register(rreq *model.RegisterRequest) error {
	photoBytes, err := base64.StdEncoding.DecodeString(rreq.Photo)
	if err != nil {
		return fmt.Errorf("cannot decode photo: %w", err)
	}

	vecotr, err := rs.ps.ExtractVector(photoBytes)
	if err != nil {
		return fmt.Errorf("cannot extract ff vector: %w", err)
	}

	user := model.User{
		Username: rreq.Username,
		Password: rreq.Password,
		FFVector: util.SerializeFloats64(vecotr),
	}

	result := rs.db.Save(&user)

	return result.Error
}
