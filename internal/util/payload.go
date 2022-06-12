package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/authentication-service/internal/model"
)

func ExPld(token string) (model.Payload, error) {
	pldb, err := base64.StdEncoding.DecodeString(strings.Split(token, ".")[2])
	if err != nil {
		return model.Payload{}, fmt.Errorf("could not decode payload: %w", err)
	}

	var pld model.Payload
	if err := json.Unmarshal(pldb, &pld); err != nil {
		return model.Payload{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}

	return pld, nil
}
