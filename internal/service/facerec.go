package service

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/authentication-service/protos/facerec"
	"github.com/sirupsen/logrus"
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
	logrus.Info("extracting ff vector")
	res, err := fs.fr.ExtractFFVectorV1(context.Background(), &facerec.ExtractFFVectorV1Request{
		Id: objectID,
	})

	if err != nil {
		logrus.Errorf("could not extract vector due to client error: %w", err)
		return nil, fmt.Errorf("could not extract vector due to client error: %w", err)
	}

	return res.Ffvc, nil
}

func (fs *FacerecService) GetDistance(x, y []float64) (float64, error) {
	logrus.Info("getting distance")
	if len(x) != len(y) {
		logrus.Errorf("could not get distance due to client error: %w")
		return 0., fmt.Errorf("different lengths")
	}

	logrus.Warn("get distance not implemented")

	return 0.3, nil
}
