package service

import (
	pb "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
	"gorm.io/gorm"
)

type Service struct {
	Db      *gorm.DB
	Session *SessionService
	Facerec pb.FaceRecognitionClient
	Token   *TokenService
	S3      s3file.S3GatewayClient
}
