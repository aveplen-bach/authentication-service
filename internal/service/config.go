package service

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/authentication-service/protos/config"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/emptypb"
)

type ConfigurationService struct {
	cc config.ConfigClient
}

func NewConfigService(cc config.ConfigClient) *ConfigurationService {
	return &ConfigurationService{
		cc: cc,
	}
}

func (cc *ConfigurationService) GetFacerecThreshold() (float64, error) {
	logrus.Info("getting facerec threshold")
	res, err := cc.cc.GetFacerecConfig(context.Background(), &emptypb.Empty{})
	if err != nil {
		logrus.Error("could not get facerec threshold due to client error")
		return 0., fmt.Errorf("could not get facerec threshold due to client error")
	}

	return res.Threshold, nil
}
