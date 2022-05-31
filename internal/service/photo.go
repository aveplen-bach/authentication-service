package service

import (
	"context"
	"fmt"
	"time"

	face_recognition_service "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
)

func (s *Service) CheckPhoto(vector []float64, photo []byte) (bool, error) {
	objectID, err := s.upload(photo)
	if err != nil {
		return false, err
	}

	derivedVector, err := s.extractVector(objectID)
	if err != nil {
		return false, err
	}

	distance, err := s.distance(vector, derivedVector)
	if err != nil {
		return false, err
	}

	return distance < 0.6, nil
}

func (s *Service) upload(photo []byte) (uint64, error) {
	id := uint64(time.Now().Unix())

	if _, err := s.S3.PutImageObject(context.Background(), &s3file.ImageObject{
		Id:       id,
		Contents: photo,
	}); err != nil {
		return 0, err
	}

	return id, nil
}

func (s *Service) extractVector(objectID uint64) ([]float64, error) {
	res, err := s.Facerec.ExtractFFVectorV1(context.Background(), &face_recognition_service.ExtractFFVectorV1Request{
		Id: objectID,
	})

	if err != nil {
		return nil, err
	}

	return res.Ffvc, nil
}

func (s *Service) distance(x, y []float64) (float64, error) {
	if len(x) != len(y) {
		return 0., fmt.Errorf("different lengths")
	}

	return 0.3, nil
}
