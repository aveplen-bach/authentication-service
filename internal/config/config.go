package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sirupsen/logrus"
)

type (
	Config struct {
		Database ConfigDatabase `yaml:"database"`
	}

	ConfigDatabase struct {
		Port     string `yaml:"port" env:"DBPORT" env-default:"5432"`
		Host     string `yaml:"host" env:"DBHOST" env-default:"localhost"`
		Name     string `yaml:"name" env:"DBNAME" env-default:"postgres"`
		User     string `yaml:"user" env:"DBUSER" env-default:"user"`
		Password string `yaml:"password" env:"DBPASSWORD"`
	}
)

func ReadConfig(path string) (Config, error) {
	var cfg Config
	err := cleanenv.ReadConfig("config.yml", &cfg)
	if err != nil {
		logrus.Fatal(err)
	}

	return cfg, nil
}
