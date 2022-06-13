package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/model"
	"github.com/sirupsen/logrus"
)

func ExPld(token string) (model.Payload, error) {
	logrus.Info("extracting payload")
	pldb, err := base64.StdEncoding.DecodeString(strings.Split(token, ".")[2])
	if err != nil {
		logrus.Errorf("could not decode payload: %w", err)
		return model.Payload{}, fmt.Errorf("could not decode payload: %w", err)
	}

	var pld model.Payload
	if err := json.Unmarshal(pldb, &pld); err != nil {
		logrus.Errorf("could not unmarshal payload: %w", err)
		return model.Payload{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}

	return pld, nil
}
