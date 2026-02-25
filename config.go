package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
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
	HTTPClientTimeout   int                 `yaml:"httpClientTimeout"` // in seconds, default 30
	Observability       ObservabilityConfig `yaml:"observability"`
}

// LoadConfigFromFile loads configuration from a YAML file
func LoadConfigFromFile(filePath string) (*Config, error) {
	// #nosec G304
	configData, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file from '%s': %w", filePath, err)
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config data: %w", err)
	}

	// Set defaults for configuration
	setConfigDefaults(&config)

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// setConfigDefaults sets default values for configuration
func setConfigDefaults(config *Config) {
	// Set HTTP client timeout default
	if config.HTTPClientTimeout == 0 {
		config.HTTPClientTimeout = 30
	}

	// Set observability defaults
	setObservabilityDefaults(&config.Observability)
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

	if obsConfig.TracingSampling <= 0 || obsConfig.TracingSampling > 1 {
		obsConfig.TracingSampling = 1.0
	}
}

// validateConfig validates the configuration for required fields and security
func validateConfig(config *Config) error {
	if config.K8SAPIURL == "" {
		return fmt.Errorf("k8sAPIURL is required")
	}
	if config.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	if config.SecretName == "" {
		return fmt.Errorf("secretName is required")
	}
	if config.LocalCertFile == "" {
		return fmt.Errorf("localCertFile is required")
	}
	if config.LocalKeyFile == "" {
		return fmt.Errorf("localKeyFile is required")
	}

	// Validate file paths for security (must be absolute paths)
	if !filepath.IsAbs(config.LocalCAFile) && config.LocalCAFile != "" {
		return fmt.Errorf("localCAFile must be an absolute path")
	}
	if !filepath.IsAbs(config.LocalCertFile) {
		return fmt.Errorf("localCertFile must be an absolute path")
	}
	if !filepath.IsAbs(config.LocalKeyFile) {
		return fmt.Errorf("localKeyFile must be an absolute path")
	}
	if !filepath.IsAbs(config.K8SCACertFile) && config.K8SCACertFile != "" {
		return fmt.Errorf("k8sCACertFile must be an absolute path")
	}

	return nil
}

// readFile reads a file and returns its content
func readFile(filePath string) ([]byte, error) {
	// #nosec G304
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	return io.ReadAll(file)
}
