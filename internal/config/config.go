package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sirupsen/logrus"
)

type (
	Config struct {
		DatabaseConfig ConfigDatabase     `yaml:"database"`
		ServerConfig   ServerConfig       `yaml:"server"`
		SJWTConfig     SJWTConfig         `yaml:"sjwt"`
		ConfigClient   ConfigClientConfig `yaml:"config-client"`
	}

	ConfigDatabase struct {
		Port     string `yaml:"port" env:"DBPORT" env-default:"5432"`
		Host     string `yaml:"host" env:"DBHOST" env-default:"localhost"`
		Name     string `yaml:"name" env:"DBNAME" env-default:"postgres"`
		User     string `yaml:"user" env:"DBUSER" env-default:"user"`
		Password string `yaml:"password" env:"DBPASSWORD"`
	}

	ServerConfig struct {
		GrpcAddr string `yaml:"grpc_addr" env-defaul:":30030"`
		ApiAddr  string `yaml:"api_addr" env-defaul:":8081"`
	}

	SJWTConfig struct {
		Secret string `yaml:"secret" env-default:"mysecret"`
	}

	ConfigClientConfig struct {
		Addr string `yaml:"addr" env-default:"localhost:30032"`
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
