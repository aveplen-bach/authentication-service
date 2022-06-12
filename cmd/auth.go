package main

import (
	"github.com/aveplen-bach/authentication-service/internal/config"
	"github.com/aveplen-bach/authentication-service/internal/server"
	"github.com/sirupsen/logrus"
)

func main() {
	cfg, err := config.ReadConfig("auth-service.yaml")
	if err != nil {
		logrus.Fatal(err)
	}
	server.Start(cfg)
}
