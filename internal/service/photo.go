package service

import "fmt"

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
	objectID, err := ps.s3.Upload(photo)
	if err != nil {
		return nil, fmt.Errorf("could not upload photo: %w", err)
	}

	vector, err := ps.fs.ExtractVector(objectID)
	if err != nil {
		return nil, fmt.Errorf("could not extract vector: %w", err)
	}

	return vector, nil
}

func (ps *PhotoService) PhotoIsCloseEnough(dbVector, photoVector []float64) (bool, error) {
	distance, err := ps.fs.GetDistance(dbVector, photoVector)
	if err != nil {
		return false, err
	}

	return distance < 0.6, nil
}
