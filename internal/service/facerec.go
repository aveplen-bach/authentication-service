package service

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/authentication-service/protos/facerec"
)

type FacerecService struct {
	fr facerec.FaceRecognitionClient
}

func NewFacerecService(fr facerec.FaceRecognitionClient) *FacerecService {
	return &FacerecService{
		fr: fr,
	}
}

func (fs *FacerecService) ExtractVector(objectID uint64) ([]float64, error) {
	res, err := fs.fr.ExtractFFVectorV1(context.Background(), &facerec.ExtractFFVectorV1Request{
		Id: objectID,
	})

	if err != nil {
		return nil, err
	}

	return res.Ffvc, nil
}

func (fs *FacerecService) GetDistance(x, y []float64) (float64, error) {
	if len(x) != len(y) {
		return 0., fmt.Errorf("different lengths")
	}

	return 0.3, nil
}
