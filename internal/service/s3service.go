package service

import (
	"context"
	"time"

	"github.com/aveplen-bach/authentication-service/protos/s3file"
)

type S3Service struct {
	s3 s3file.S3GatewayClient
}

func NewS3Service(s3 s3file.S3GatewayClient) *S3Service {
	return &S3Service{
		s3: s3,
	}
}

func (s3 *S3Service) Upload(photo []byte) (uint64, error) {
	id := uint64(time.Now().Unix())

	if _, err := s3.s3.PutImageObject(context.Background(), &s3file.ImageObject{
		Id:       id,
		Contents: photo,
	}); err != nil {
		return 0, err
	}

	return id, nil
}
