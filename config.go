package main

import (
	"fmt"
	"io"
	"os"

	"github.com/goccy/go-yaml"
)

// Config represents the application configuration
type Config struct {
	K8SAPIURL           string              `yaml:"k8sAPIURL"`
	K8SCACertFile       string              `yaml:"k8sCACertFile"`
	SkipTLSVerification bool                `yaml:"skipTLSVerification"`
	Token               string              `yaml:"token"`
	Namespace           string              `yaml:"namespace"`
	SecretName          string              `yaml:"secretName"`
	LocalCAFile         string              `yaml:"localCAFile"`
	LocalCertFile       string              `yaml:"localCertFile"`
	LocalKeyFile        string              `yaml:"localKeyFile"`
	ReloadCommand       string              `yaml:"reloadCommand"`
	UseIntermediateCA   bool                `yaml:"useIntermediateCA"`
	Observability       ObservabilityConfig `yaml:"observability"`
}

// LoadConfigFromFile loads configuration from a YAML file
func LoadConfigFromFile(filePath string) (*Config, error) {
	configData, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file from '%s': %w", filePath, err)
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config data: %w", err)
	}

	// Set defaults for observability if not specified
	setObservabilityDefaults(&config.Observability)

	return &config, nil
}

// setObservabilityDefaults sets default values for observability configuration
func setObservabilityDefaults(obsConfig *ObservabilityConfig) {
	if obsConfig.LogLevel == "" {
		obsConfig.LogLevel = "info"
	}
	if obsConfig.LogFormat == "" {
		obsConfig.LogFormat = "text"
	}
	if obsConfig.MetricsPort == 0 {
		obsConfig.MetricsPort = 8080
	}
	if obsConfig.MetricsPath == "" {
		obsConfig.MetricsPath = "/metrics"
	}
	if obsConfig.MetricsAddress == "" {
		obsConfig.MetricsAddress = "0.0.0.0"
	}
	if obsConfig.ServiceName == "" {
		obsConfig.ServiceName = "fetch-k8s-cert"
	}
	if obsConfig.ServiceVersion == "" {
		obsConfig.ServiceVersion = version
	}
	if obsConfig.TracingSampling <= 0 || obsConfig.TracingSampling > 1 {
		obsConfig.TracingSampling = 1.0
	}
}

// readFile reads a file and returns its content
func readFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return io.ReadAll(file)
}
