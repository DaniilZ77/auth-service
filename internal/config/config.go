package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	HttpPort        string        `yaml:"http_port"`
	JwtSecret       string        `yaml:"jwt_secret"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
	DBURL           string        `yaml:"db_url"`
	LogLevel        string        `yaml:"log_level"`
	WebhookURL      string        `yaml:"webhook_url"`
}

func MustConfig() *Config {
	config, err := NewConfig()
	if err != nil {
		panic(err)
	}

	return config
}

func NewConfig() (*Config, error) {
	configPath, ok := getConfigPath()
	if !ok {
		return nil, errors.New("config path is not set")
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err = yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

func getConfigPath() (configPath string, ok bool) {
	flag.StringVar(&configPath, "config_path", "", "path to config")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	return configPath, configPath != ""
}
