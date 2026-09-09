package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	testNamespace      = "test-namespace"
	testSecret         = "test-secret"
	testToken          = "test-token"
	testCertFile       = "/tmp/cert.pem"
	testKeyFile        = "/tmp/key.pem"
	testCAFile         = "/tmp/ca.pem"
	testK8sAPIURL      = "https://kubernetes.example.com"
	testLogLevel       = "info"
	testMetricsPath    = "/metrics"
	testMetricsAddr    = "0.0.0.0"
	testTraceEndpoint  = "http://localhost:4318"
	testCertCN         = "Test Certificate"
	testServerCN       = "Test Server"
	testServerName     = "test.example.com"
	testRootCA         = "Test Root CA"
	testIntermediateCA = "Test Intermediate CA"
)

// Test GetTLSBundle error paths
func TestK8sClient_GetTLSBundle_ServerError(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.GetTLSBundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for server error response")
	}
}

func TestK8sClient_GetTLSBundle_Unauthorized(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.GetTLSBundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for unauthorized response")
	}
}

func TestK8sClient_GetTLSBundle_Forbidden(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.GetTLSBundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for forbidden response")
	}
}

func TestK8sClient_GetTLSBundle_NotFound(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.GetTLSBundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for not found response")
	}
}

func TestK8sClient_GetTLSBundle_InvalidResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	_, err = client.GetTLSBundle(context.Background())
	if err == nil {
		t.Fatal("Expected error for invalid response body")
	}
}

// Test NewK8sClient with various configurations
func TestNewK8sClient_SkipTLSVerification(t *testing.T) {
	config := Config{
		SkipTLSVerification: true,
		Token:               testToken,
		Namespace:           testNamespace,
		SecretName:          testSecret,
	}

	logger := logrus.New()
	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

func TestNewK8sClient_WithCACertFile(t *testing.T) {
	// Create a temporary CA cert file
	tempDir := t.TempDir()
	caFile := filepath.Join(tempDir, "ca.crt")

	// Generate a self-signed CA cert
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	pemData, err := certificateToPEM(cert)
	if err != nil {
		t.Fatalf("Failed to encode certificate to PEM: %v", err)
	}

	err = os.WriteFile(caFile, pemData, 0644)
	if err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	config := Config{
		K8SCACertFile: caFile,
		Token:         testToken,
		Namespace:     testNamespace,
		SecretName:    testSecret,
	}

	logger := logrus.New()
	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client with CA cert: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

func TestNewK8sClient_InvalidCACertFile(t *testing.T) {
	config := Config{
		K8SCACertFile: "/nonexistent/ca.crt",
		Token:         testToken,
		Namespace:     testNamespace,
		SecretName:    testSecret,
	}

	logger := logrus.New()
	_, err := NewK8sClient(config, logger, nil)
	if err == nil {
		t.Fatal("Expected error for invalid CA cert file")
	}
}

func TestNewK8sClient_CustomTimeout(t *testing.T) {
	config := Config{
		Token:             testToken,
		Namespace:         testNamespace,
		SecretName:        testSecret,
		HTTPClientTimeout: 60,
	}

	logger := logrus.New()
	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
}

// Test FileManager.TriggerReload
func TestFileManager_TriggerReload_EmptyCommand(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	fm := NewFileManager(config, logger, nil)

	err := fm.TriggerReload(context.Background())
	if err != nil {
		t.Fatalf("Expected no error for empty reload command, got: %v", err)
	}
}

func TestFileManager_TriggerReload_Success(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
		ReloadCommand: "echo test",
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	fm := NewFileManager(config, logger, nil)

	err := fm.TriggerReload(context.Background())
	if err != nil {
		t.Fatalf("Expected no error for successful reload, got: %v", err)
	}
}

func TestFileManager_TriggerReload_Failure(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
		ReloadCommand: "false",
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	fm := NewFileManager(config, logger, nil)

	err := fm.TriggerReload(context.Background())
	if err == nil {
		t.Fatal("Expected error for failing reload command")
	}
}

// Test UpdateCertificateFiles
func TestFileManager_UpdateCertificateFiles(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	fm := NewFileManager(config, logger, nil)

	bundle := &TLSBundle{
		CAData:   []byte("test-ca-data"),
		CertData: []byte("test-cert-data"),
		KeyData:  []byte("test-key-data"),
	}

	changed, err := fm.UpdateCertificateFiles(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !changed {
		t.Fatal("Expected files to be changed (new files created)")
	}

	// Verify files were created
	for _, path := range []string{config.LocalCAFile, config.LocalCertFile, config.LocalKeyFile} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected file %s to exist", path)
		}
	}
}

func TestFileManager_UpdateCertificateFiles_NoChange(t *testing.T) {
	tempDir := t.TempDir()
	config := Config{
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	fm := NewFileManager(config, logger, nil)

	bundle := &TLSBundle{
		CAData:   []byte("test-ca-data"),
		CertData: []byte("test-cert-data"),
		KeyData:  []byte("test-key-data"),
	}

	// First call creates the files
	_, err := fm.UpdateCertificateFiles(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Expected no error on first update, got: %v", err)
	}

	// Second call should detect no changes
	changed, err := fm.UpdateCertificateFiles(context.Background(), bundle)
	if err != nil {
		t.Fatalf("Expected no error on second update, got: %v", err)
	}

	if changed {
		t.Fatal("Expected no changes on second update")
	}
}

// Test config validation
func TestValidateConfig_MissingK8sAPIURL(t *testing.T) {
	config := Config{
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for missing k8sAPIURL")
	}
}

func TestValidateConfig_MissingNamespace(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for missing namespace")
	}
}

func TestValidateConfig_MissingSecretName(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for missing secretName")
	}
}

func TestValidateConfig_MissingLocalCertFile(t *testing.T) {
	config := Config{
		K8SAPIURL:    "https://kubernetes.example.com",
		Namespace:    testNamespace,
		SecretName:   testSecret,
		LocalKeyFile: testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for missing localCertFile")
	}
}

func TestValidateConfig_MissingLocalKeyFile(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for missing localKeyFile")
	}
}

func TestValidateConfig_RelativeCertPath(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: "relative/path/cert.pem",
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for relative cert path")
	}
}

func TestValidateConfig_RelativeKeyPath(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
		LocalKeyFile:  "relative/path/key.pem",
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for relative key path")
	}
}

func TestValidateConfig_RelativeCAPath(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCAFile:   "relative/path/ca.pem",
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for relative CA path")
	}
}

func TestValidateConfig_RelativeK8sCACertPath(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
		K8SCACertFile: "relative/ca.crt",
	}

	err := validateConfig(&config)
	if err == nil {
		t.Fatal("Expected error for relative k8sCACertFile path")
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCAFile:   testCAFile,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err != nil {
		t.Fatalf("Expected no error for valid config, got: %v", err)
	}
}

func TestValidateConfig_NoCAFileValid(t *testing.T) {
	config := Config{
		K8SAPIURL:     testK8sAPIURL,
		Namespace:     testNamespace,
		SecretName:    testSecret,
		LocalCertFile: testCertFile,
		LocalKeyFile:  testKeyFile,
	}

	err := validateConfig(&config)
	if err != nil {
		t.Fatalf("Expected no error for valid config without CA file, got: %v", err)
	}
}

// Test config defaults
func TestSetConfigDefaults(t *testing.T) {
	config := Config{}

	setConfigDefaults(&config)

	if config.HTTPClientTimeout != 30 {
		t.Errorf("Expected default HTTPClientTimeout of 30, got %d", config.HTTPClientTimeout)
	}
}

func TestSetConfigDefaults_CustomTimeout(t *testing.T) {
	config := Config{HTTPClientTimeout: 60}

	setConfigDefaults(&config)

	if config.HTTPClientTimeout != 60 {
		t.Errorf("Expected custom HTTPClientTimeout of 60, got %d", config.HTTPClientTimeout)
	}
}

func TestSetObservabilityDefaults(t *testing.T) {
	obs := ObservabilityConfig{}

	setObservabilityDefaults(&obs)

	if obs.LogLevel != testLogLevel {
		t.Errorf("Expected default LogLevel 'info', got '%s'", obs.LogLevel)
	}

	if obs.LogFormat != "text" {
		t.Errorf("Expected default LogFormat 'text', got '%s'", obs.LogFormat)
	}

	if obs.MetricsPort != 8080 {
		t.Errorf("Expected default MetricsPort 8080, got %d", obs.MetricsPort)
	}

	if obs.MetricsPath != testMetricsPath {
		t.Errorf("Expected default MetricsPath '/metrics', got '%s'", obs.MetricsPath)
	}

	if obs.MetricsAddress != testMetricsAddr {
		t.Errorf("Expected default MetricsAddress '0.0.0.0', got '%s'", obs.MetricsAddress)
	}

	if obs.TracingSampling != 1.0 {
		t.Errorf("Expected default TracingSampling 1.0, got %f", obs.TracingSampling)
	}
}

func TestSetObservabilityDefaults_InvalidSampling(t *testing.T) {
	obs := ObservabilityConfig{
		TracingSampling: 2.0,
	}

	setObservabilityDefaults(&obs)

	if obs.TracingSampling != 1.0 {
		t.Errorf("Expected TracingSampling to be corrected to 1.0, got %f", obs.TracingSampling)
	}
}

func TestSetObservabilityDefaults_ZeroSampling(t *testing.T) {
	obs := ObservabilityConfig{
		TracingSampling: 0,
	}

	setObservabilityDefaults(&obs)

	if obs.TracingSampling != 1.0 {
		t.Errorf("Expected TracingSampling to be corrected to 1.0, got %f", obs.TracingSampling)
	}
}

func TestSetObservabilityDefaults_NegativeSampling(t *testing.T) {
	obs := ObservabilityConfig{
		TracingSampling: -1.0,
	}

	setObservabilityDefaults(&obs)

	if obs.TracingSampling != 1.0 {
		t.Errorf("Expected TracingSampling to be corrected to 1.0, got %f", obs.TracingSampling)
	}
}

// Test LoadConfigFromFile error cases
func TestLoadConfigFromFile_FileNotFound(t *testing.T) {
	_, err := LoadConfigFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("Expected error for non-existent file")
	}
}

func TestLoadConfigFromFile_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	err := os.WriteFile(configFile, []byte("invalid: yaml: content: ["), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Fatal("Expected error for invalid YAML")
	}
}

func TestLoadConfigFromFile_InvalidConfig(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	// Config with missing required fields
	configContent := `
k8sAPIURL: https://kubernetes.example.com
namespace: test-namespace
secretName: test-secret
localCertFile: relative/path/cert.pem
localKeyFile: /tmp/key.pem
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Fatal("Expected error for invalid config (relative cert path)")
	}
}

// Test LoadConfigFromFile with observability defaults
func TestLoadConfigFromFile_WithObservability(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "config.yaml")

	configContent := `
k8sAPIURL: https://kubernetes.example.com:6443
namespace: test-namespace
secretName: test-secret
localCAFile: /tmp/ca.pem
localCertFile: /tmp/cert.pem
localKeyFile: /tmp/key.pem
httpClientTimeout: 60
observability:
  enableMetrics: true
  logLevel: debug
  logFormat: json
  metricsPort: 9090
  metricsPath: /prometheus
  metricsAddress: 127.0.0.1
  enableTracing: false
  tracingSampling: 0.5
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if config.HTTPClientTimeout != 60 {
		t.Errorf("Expected HTTPClientTimeout 60, got %d", config.HTTPClientTimeout)
	}

	if config.Observability.LogLevel != "debug" {
		t.Errorf("Expected LogLevel 'debug', got '%s'", config.Observability.LogLevel)
	}

	if config.Observability.LogFormat != "json" {
		t.Errorf("Expected LogFormat 'json', got '%s'", config.Observability.LogFormat)
	}

	if config.Observability.MetricsPort != 9090 {
		t.Errorf("Expected MetricsPort 9090, got %d", config.Observability.MetricsPort)
	}

	if config.Observability.MetricsPath != "/prometheus" {
		t.Errorf("Expected MetricsPath '/prometheus', got '%s'", config.Observability.MetricsPath)
	}

	if config.Observability.MetricsAddress != "127.0.0.1" {
		t.Errorf("Expected MetricsAddress '127.0.0.1', got '%s'", config.Observability.MetricsAddress)
	}

	if config.Observability.TracingSampling != 0.5 {
		t.Errorf("Expected TracingSampling 0.5, got %f", config.Observability.TracingSampling)
	}
}

// Test Metrics helper methods - use a single manager to avoid duplicate registration
func TestMetrics_Helpers(t *testing.T) {
	obs, err := NewObservabilityManager(ObservabilityConfig{
		EnableMetrics: false, // Disable metrics to avoid registration conflicts
	})
	if err != nil {
		t.Fatalf("Failed to create observability manager: %v", err)
	}

	metrics := obs.Metrics()
	// With metrics disabled, this should be nil - test nil receiver path
	if metrics != nil {
		t.Skip("Metrics was not nil, skipping - test with nil receiver below")
	}
}

// Test Metrics with nil receiver
func TestMetrics_NilReceiver(t *testing.T) {
	var m *Metrics

	// All these should not panic with nil receiver
	m.RecordFetchAttempt("ns", "secret", "success")
	m.RecordFetchDuration("ns", "secret", "success", 1*time.Second)
	m.RecordFetchError("ns", "secret", "network")
	m.SetCertificateAge("ns", "secret", 24*time.Hour)
	m.SetCertificateExpiry("ns", "secret", 30*24*time.Hour)
	m.RecordFileWrite("ca", "created")
	m.RecordFileWriteError("ca", "open_failed")
	m.RecordReloadAttempt("success")
	m.RecordReloadError("command_failed")
	m.RecordCertValidation("chain", "valid")
	m.RecordCAExtraction("chain", "success")
	m.RecordCAExtractionError("parse_error")
}

// Test ObservabilityManager helper methods
func TestObservabilityManager_Helpers(t *testing.T) {
	obs, err := NewObservabilityManager(ObservabilityConfig{})
	if err != nil {
		t.Fatalf("Failed to create observability manager: %v", err)
	}

	logger := obs.Logger()
	if logger == nil {
		t.Fatal("Expected non-nil logger")
	}

	// Metrics should be nil when disabled
	metrics := obs.Metrics()
	if metrics != nil {
		t.Fatal("Expected nil metrics when disabled")
	}
}

func TestObservabilityManager_WithTracing(t *testing.T) {
	obs, err := NewObservabilityManager(ObservabilityConfig{
		EnableTracing:   true,
		TracingEndpoint: testTraceEndpoint,
	})
	if err != nil {
		t.Fatalf("Failed to create observability manager: %v", err)
	}

	tracer := obs.Tracer()
	if tracer == nil {
		t.Fatal("Expected non-nil tracer when tracing enabled")
	}
}

func TestObservabilityManager_Shutdown(t *testing.T) {
	obs, err := NewObservabilityManager(ObservabilityConfig{})
	if err != nil {
		t.Fatalf("Failed to create observability manager: %v", err)
	}

	ctx := context.Background()
	err = obs.Shutdown(ctx)
	if err != nil {
		t.Fatalf("Expected no error on shutdown, got: %v", err)
	}
}

// Test ExtractTLSBundleFromSecret with invalid base64
func TestExtractTLSBundleFromSecret_InvalidBase64Data(t *testing.T) {
	secretData := `{"data": {"ca.crt": "invalid-base64!!!", "tls.crt": "Y2VydC1kYXRh", "tls.key": "a2V5LWRhdGE="}}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config, nil, nil)
	if err == nil {
		t.Fatal("Expected error for invalid base64 data")
	}
}

func TestExtractTLSBundleFromSecret_MissingData(t *testing.T) {
	secretData := `{"data": {}}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config, nil, nil)
	if err == nil {
		t.Fatal("Expected error for missing data")
	}
}

func TestExtractTLSBundleFromSecret_MissingTLSKey(t *testing.T) {
	secretData := `{"data": {"tls.crt": "Y2VydC1kYXRh"}}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config, nil, nil)
	if err == nil {
		t.Fatal("Expected error for missing tls.key")
	}
}

func TestExtractTLSBundleFromSecret_EmptySecret(t *testing.T) {
	secretData := `{"data": null}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config, nil, nil)
	if err == nil {
		t.Fatal("Expected error for null data")
	}
}

func TestExtractTLSBundleFromSecret_NoDataField(t *testing.T) {
	secretData := `{}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config, nil, nil)
	if err == nil {
		t.Fatal("Expected error for missing data field")
	}
}

// Test GetTLSBundle with working server and valid response
func TestK8sClient_GetTLSBundle_Success(t *testing.T) {
	testCA := []byte("test-ca-data")
	testCert := []byte("test-cert-data")
	testKey := []byte("test-key-data")

	secretResponse := map[string]interface{}{
		"data": map[string]string{
			"ca.crt":  base64.StdEncoding.EncodeToString(testCA),
			"tls.crt": base64.StdEncoding.EncodeToString(testCert),
			"tls.key": base64.StdEncoding.EncodeToString(testKey),
		},
	}

	responseBody, err := json.Marshal(secretResponse)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}))
	defer mockServer.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	config := Config{
		K8SAPIURL:  mockServer.URL,
		Token:      base64.StdEncoding.EncodeToString([]byte(testToken)),
		Namespace:  testNamespace,
		SecretName: testSecret,
	}

	client, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	bundle, err := client.GetTLSBundle(context.Background())
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if string(bundle.CAData) != string(testCA) {
		t.Errorf("Expected CA data '%s', got '%s'", testCA, bundle.CAData)
	}

	if string(bundle.CertData) != string(testCert) {
		t.Errorf("Expected cert data '%s', got '%s'", testCert, bundle.CertData)
	}

	if string(bundle.KeyData) != string(testKey) {
		t.Errorf("Expected key data '%s', got '%s'", testKey, bundle.KeyData)
	}
}

// Test parseCertificateInfo (currently 0% coverage)
func TestParseCertificateInfo(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: testCertCN,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{testServerName},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	pemData, err := certificateToPEM(cert)
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	parsedCert, err := parseCertificateInfo(pemData)
	if err != nil {
		t.Fatalf("parseCertificateInfo failed: %v", err)
	}

	if parsedCert.Subject.CommonName != testCertCN {
		t.Errorf("Expected CommonName 'Test Certificate', got '%s'", parsedCert.Subject.CommonName)
	}

	if len(parsedCert.DNSNames) != 1 || parsedCert.DNSNames[0] != testServerName {
		t.Errorf("Expected DNSNames ['test.example.com'], got %v", parsedCert.DNSNames)
	}
}

// Test bytesEqual function
func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []byte{}, []byte{}, true},
		{"same content", []byte("hello"), []byte("hello"), true},
		{"different content", []byte("hello"), []byte("world"), false},
		{"different length", []byte("hello"), []byte("hi"), false},
		{"one nil", []byte("hello"), nil, false},
		{"other nil", nil, []byte("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("bytesEqual(%v, %v) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}
