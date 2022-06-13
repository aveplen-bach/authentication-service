package service

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type PhotoService struct {
	fs *FacerecService
	s3 *S3Service
}

func NewPhotoService(
	fs *FacerecService,
	s3 *S3Service,
) *PhotoService {
	return &PhotoService{
		fs: fs,
		s3: s3,
	}
}

func (ps *PhotoService) ExtractVector(photo []byte) ([]float64, error) {
	logrus.Info("extracting ff vector")
	objectID, err := ps.s3.Upload(photo)
	if err != nil {
		logrus.Errorf("could not upload photo: %w", err)
		return nil, fmt.Errorf("could not upload photo: %w", err)
	}

	vector, err := ps.fs.ExtractVector(objectID)
	if err != nil {
		logrus.Errorf("could not extract vector: %w", err)
		return nil, fmt.Errorf("could not extract vector: %w", err)
	}

	return vector, nil
}

func (ps *PhotoService) PhotoIsCloseEnough(dbVector, photoVector []float64) (bool, error) {
	distance, err := ps.fs.GetDistance(dbVector, photoVector)
	if err != nil {
		logrus.Errorf("could not get distance: %w", err)
		return false, fmt.Errorf("could not get distance: %w", err)
	}

	return distance < 0.6, nil
}
