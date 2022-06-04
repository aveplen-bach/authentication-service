package service

import (
	"context"
	"fmt"
	"time"

	face_recognition_service "github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/aveplen-bach/authentication-service/protos/s3file"
)

type PhotoService struct {
	s3 s3file.S3GatewayClient
	fr face_recognition_service.FaceRecognitionClient
}

func NewPhotoService(
	s3 s3file.S3GatewayClient,
	fr face_recognition_service.FaceRecognitionClient,
) *PhotoService {
	return &PhotoService{
		s3: s3,
		fr: fr,
	}
}

func (ps *PhotoService) PhotoIsCloseEnough(vector []float64, photo []byte) (bool, error) {
	objectID, err := ps.upload(photo)
	if err != nil {
		return false, err
	}

	derivedVector, err := ps.extractVector(objectID)
	if err != nil {
		return false, err
	}

	distance, err := ps.getDistance(vector, derivedVector)
	if err != nil {
		return false, err
	}

	return distance < 0.6, nil
}

func (ps *PhotoService) upload(photo []byte) (uint64, error) {
	id := uint64(time.Now().Unix())

	if _, err := ps.s3.PutImageObject(context.Background(), &s3file.ImageObject{
		Id:       id,
		Contents: photo,
	}); err != nil {
		return 0, err
	}

	return id, nil
}

func (ps *PhotoService) extractVector(objectID uint64) ([]float64, error) {
	res, err := ps.fr.ExtractFFVectorV1(context.Background(), &face_recognition_service.ExtractFFVectorV1Request{
		Id: objectID,
	})

	if err != nil {
		return nil, err
	}

	return res.Ffvc, nil
}

func (ps *PhotoService) getDistance(x, y []float64) (float64, error) {
	if len(x) != len(y) {
		return 0., fmt.Errorf("different lengths")
	}

	return 0.3, nil
}
