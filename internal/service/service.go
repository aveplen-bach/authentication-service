package service

import (
	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"gorm.io/gorm"
)

type Service struct {
	Db      *gorm.DB
	Session *SessionService
	Token   *TokenService
	Facerec pb.FaceRecognitionClient
	S3      s3file.S3GatewayClient
}

func NewService(db *gorm.DB,
	session *SessionService,
	token *TokenService,
	facerec pb.FaceRecognitionClient,
	s3 s3file.S3GatewayClient,
) *Service {

	return &Service{
		Db:      db,
		Session: session,
		Facerec: facerec,
		Token:   token,
		S3:      s3,
	}
}
