package config

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sirupsen/logrus"
)

type (
	Config struct {
		DatabaseConfig      ConfigDatabase      `yaml:"database"`
		ServerConfig        ServerConfig        `yaml:"server"`
		SJWTConfig          SJWTConfig          `yaml:"sjwt"`
		ConfigClient        ConfigClientConfig  `yaml:"config-client"`
		S3ClientConfig      S3ClientConfig      `yaml:"s3-client"`
		FacerecClientConfig FacerecClientConfig `yaml:"facerec-client"`
	}

	ConfigDatabase struct {
		Port     string `yaml:"port" env:"DBPORT" env-default:"5432"`
		Host     string `yaml:"host" env:"DBHOST" env-default:"localhost"`
		Name     string `yaml:"name" env:"DBNAME" env-default:"postgres"`
		User     string `yaml:"user" env:"DBUSER" env-default:"user"`
		Password string `yaml:"password" env:"DBPASSWORD"`
	}

	ServerConfig struct {
		GrpcAddr string `yaml:"grpc_addr" env:"GRPC_LISTEN_ADDR" env-defaul:":30031"`
		ApiAddr  string `yaml:"api_addr" env:"HTTP_LISTEN_ADDR" env-defaul:":8081"`
	}

	SJWTConfig struct {
		Secret string `yaml:"secret" env:"SJWT_SECRET" env-default:"mysecret"`
	}

	ConfigClientConfig struct {
		Addr string `yaml:"addr" env:"CONFIG_CLIENT_ADDR" env-default:"localhost:30032"`
	}

	S3ClientConfig struct {
		Addr string `yaml:"addr" env:"S3_CLIENT_ADDR" env-default:"localhost:30033"`
	}

	FacerecClientConfig struct {
		Addr string `yaml:"addr" env:"FACEREC_CLIENT_ADDR" env-default:"localhost:30034"`
	}
)

func ReadConfig(path string) (Config, error) {
	var cfg Config
	err := cleanenv.ReadConfig("auth-service.yaml", &cfg)
	if err != nil {
		logrus.Fatal(err)
	}

	return cfg, nil
}
