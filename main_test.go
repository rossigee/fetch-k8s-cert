package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

type TestHook struct {
	Messages []string
}

func (hook *TestHook) Fire(entry *logrus.Entry) error {
	hook.Messages = append(hook.Messages, entry.Message)
	return nil
}

func (hook *TestHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func TestMainFunction_Success(t *testing.T) {
	testCA := []byte("base64-encoded-ca\n")
	encodedCA := base64.StdEncoding.EncodeToString(testCA)
	testCert := []byte("base64-encoded-cert\n")
	encodedCert := base64.StdEncoding.EncodeToString(testCert)
	testKey := []byte("base64-encoded-key\n")
	encodedKey := base64.StdEncoding.EncodeToString(testKey)
	requestBody := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`, encodedCA, encodedCert, encodedKey)

	runTestWithConfig(t, requestBody, func(config Config) {
		ctx := context.Background()
		err := run(ctx, config)
		if err != nil {
			t.Fatalf("run() failed: %v", err)
		}

		caFile, err := os.Open(config.LocalCAFile)
		if err != nil {
			t.Fatalf("Failed to open CA certificate file: %v", err)
		}
		defer func() { _ = caFile.Close() }()
		var caData bytes.Buffer
		_, err = io.Copy(&caData, caFile)
		if err != nil {
			t.Fatalf("Failed to read CA certificate data: %v", err)
		}
		if !bytes.Equal(caData.Bytes(), testCA) {
			t.Errorf("CA certificate data does not match expected")
		}
	})
}

func TestMainFunction_Failure(t *testing.T) {
	hook := &TestHook{}
	log.AddHook(hook)

	testCA := []byte("base64-encoded-ca\n")
	testCert := []byte("base64-encoded-cert\n")
	testKey := []byte("base64-encoded-key\n")
	requestBody := fmt.Sprintf(`{"data": {"ca.cert": "%s", "tls.crt": "%s", "tls.key": "%s"}}`, testCA, testCert, testKey)

	runTestWithConfig(t, requestBody, func(config Config) {
		ctx := context.Background()
		err := run(ctx, config)
		if err == nil {
			t.Errorf("Expected run() to fail, but it succeeded")
		}

		// Check if the expected error message is logged or returned
		if !containsLogMessage(hook.Messages, "failed to get TLS bundle") && !strings.Contains(err.Error(), "failed to get TLS bundle") {
			t.Errorf("Expected error message not found in logs or error: %v", err)
		}
	})
}

func TestMainFunction_InvalidConfig(t *testing.T) {
	hook := &TestHook{}
	log.AddHook(hook)

	testCA := []byte("base64-encoded-ca\n")
	encodedCA := base64.StdEncoding.EncodeToString(testCA)
	testCert := []byte("base64-encoded-cert\n")
	encodedCert := base64.StdEncoding.EncodeToString(testCert)
	testKey := []byte("base64-encoded-key\n")
	encodedKey := base64.StdEncoding.EncodeToString(testKey)
	requestBody := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`, encodedCA, encodedCert, encodedKey)

	runTestWithConfig(t, requestBody, func(config Config) {
		// Modify the config to use an invalid path
		config.LocalCAFile = "/etc/hosts"

		ctx := context.Background()
		err := run(ctx, config)
		if err == nil {
			t.Errorf("Expected run() to fail, but it succeeded")
		}

		// Check if the expected error message is logged or returned
		if !containsLogMessage(hook.Messages, "failed to update certificate files") && !strings.Contains(err.Error(), "failed to update certificate files") {
			t.Errorf("Expected error message not found in logs or error: %v", err)
		}
	})
}

func TestMainFunction_ReloadFailure(t *testing.T) {
	hook := &TestHook{}
	log.AddHook(hook)

	testCA := []byte("base64-encoded-ca\n")
	encodedCA := base64.StdEncoding.EncodeToString(testCA)
	testCert := []byte("base64-encoded-cert\n")
	encodedCert := base64.StdEncoding.EncodeToString(testCert)
	testKey := []byte("base64-encoded-key\n")
	encodedKey := base64.StdEncoding.EncodeToString(testKey)
	requestBody := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`, encodedCA, encodedCert, encodedKey)

	runTestWithConfig_CustomReload(t, requestBody, "false", func(config Config) {
		ctx := context.Background()
		err := run(ctx, config)
		if err == nil {
			t.Errorf("Expected run() to fail due to reload command failure, but it succeeded")
		}

		// Check if the expected error message is logged or returned
		if !containsLogMessage(hook.Messages, "failed to trigger reload") && !strings.Contains(err.Error(), "failed to trigger reload") {
			t.Errorf("Expected error message not found in logs or error: %v", err)
		}
	})
}

func createMockServer(statusCode int, responseBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, err := fmt.Fprintln(w, responseBody)
		_ = err
	}))
}

func containsLogMessage(messages []string, targetMessage string) bool {
	for _, message := range messages {
		if strings.Contains(message, targetMessage) {
			return true
		}
	}
	return false
}

func runTestWithConfig(t *testing.T, requestBody string, testFunc func(config Config)) {
	runTestWithConfig_CustomReload(t, requestBody, "echo test-reload", testFunc)
}

func runTestWithConfig_CustomReload(t *testing.T, requestBody string, reloadCmd string, testFunc func(config Config)) {
	tempDir := t.TempDir()

	mockServer := createMockServer(http.StatusOK, requestBody)
	defer mockServer.Close()

	caFilePath := filepath.Join(tempDir, "test-ca.pem")
	certFilePath := filepath.Join(tempDir, "test-cert.pem")
	keyFilePath := filepath.Join(tempDir, "test-key.pem")

	testConfig := Config{
		K8SAPIURL:     mockServer.URL,
		Token:         base64.StdEncoding.EncodeToString([]byte("test-token")),
		Namespace:     "test-namespace",
		SecretName:    "test-secret-name",
		LocalCAFile:   caFilePath,
		LocalCertFile: certFilePath,
		LocalKeyFile:  keyFilePath,
		ReloadCommand: reloadCmd,
	}

	testFunc(testConfig)
}

// Test helper functions for creating certificates

func generateCertificate(template, parent *x509.Certificate, publicKey, privateKey interface{}) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func createTestCertificateChain() ([]byte, error) {
	// Generate keys
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create root CA certificate
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Root CA"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertPEM, err := generateCertificate(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	// Create intermediate CA certificate
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Intermediate CA"},
			CommonName:   "Test Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Parse root certificate to use as parent
	rootBlock, _ := pem.Decode(rootCertPEM)
	rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return nil, err
	}

	intermediateCertPEM, err := generateCertificate(intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	// Create server certificate
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Server"},
			CommonName:   "test.example.com",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	// Parse intermediate certificate to use as parent
	intermediateBlock, _ := pem.Decode(intermediateCertPEM)
	intermediateCert, err := x509.ParseCertificate(intermediateBlock.Bytes)
	if err != nil {
		return nil, err
	}

	serverCertPEM, err := generateCertificate(serverTemplate, intermediateCert, &serverKey.PublicKey, intermediateKey)
	if err != nil {
		return nil, err
	}

	// Combine server + intermediate + root certificates into chain
	var chainBuffer bytes.Buffer
	chainBuffer.Write(serverCertPEM)
	chainBuffer.Write(intermediateCertPEM)
	chainBuffer.Write(rootCertPEM)

	return chainBuffer.Bytes(), nil
}

// Test cases for intermediate CA extraction

func TestExtractIntermediateCAFromCertChain_Success(t *testing.T) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		t.Fatalf("Failed to create test certificate chain: %v", err)
	}

	intermediatePEM, err := ExtractIntermediateCAFromCertChain(certChain)
	if err != nil {
		t.Fatalf("Failed to extract intermediate CA: %v", err)
	}

	// Parse the extracted intermediate CA
	block, _ := pem.Decode(intermediatePEM)
	if block == nil {
		t.Fatal("Failed to decode intermediate CA PEM")
	}

	intermediateCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse intermediate CA certificate: %v", err)
	}

	// Verify it's the intermediate CA
	if intermediateCert.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Expected intermediate CA common name 'Test Intermediate CA', got '%s'", intermediateCert.Subject.CommonName)
	}

	if !intermediateCert.IsCA {
		t.Error("Expected intermediate certificate to be a CA")
	}
}

func TestExtractIntermediateCAFromCertChain_InsufficientCerts(t *testing.T) {
	// Create a chain with only one certificate
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}

	singleCertPEM, _ := generateCertificate(rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	_, err := ExtractIntermediateCAFromCertChain(singleCertPEM)
	if err == nil {
		t.Error("Expected error for insufficient certificates, got nil")
	}

	expectedError := "certificate chain must contain at least 2 certificates"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestExtractIntermediateCAFromCertChain_InvalidPEM(t *testing.T) {
	invalidPEM := []byte("invalid PEM data")

	_, err := ExtractIntermediateCAFromCertChain(invalidPEM)
	if err == nil {
		t.Error("Expected error for invalid PEM, got nil")
	}
}

func TestExtractTLSBundleWithIntermediateCA(t *testing.T) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		t.Fatalf("Failed to create test certificate chain: %v", err)
	}

	// Create a mock secret with certificate chain
	encodedCertChain := base64.StdEncoding.EncodeToString(certChain)
	encodedCA := base64.StdEncoding.EncodeToString([]byte("mock-root-ca"))
	encodedKey := base64.StdEncoding.EncodeToString([]byte("mock-private-key"))

	secretData := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`,
		encodedCA, encodedCertChain, encodedKey)

	// Test with useIntermediateCA enabled
	config := Config{UseIntermediateCA: true}
	bundle, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err != nil {
		t.Fatalf("Failed to extract TLS bundle: %v", err)
	}

	// Verify the CA data is the intermediate CA
	block, _ := pem.Decode(bundle.CAData)
	if block == nil {
		t.Fatal("Failed to decode CA data")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	if caCert.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("Expected intermediate CA, got '%s'", caCert.Subject.CommonName)
	}
}

func TestExtractTLSBundleWithoutIntermediateCA(t *testing.T) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		t.Fatalf("Failed to create test certificate chain: %v", err)
	}

	// Create a mock secret with certificate chain
	encodedCertChain := base64.StdEncoding.EncodeToString(certChain)
	mockRootCA := []byte("mock-root-ca-data")
	encodedCA := base64.StdEncoding.EncodeToString(mockRootCA)
	encodedKey := base64.StdEncoding.EncodeToString([]byte("mock-private-key"))

	secretData := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`,
		encodedCA, encodedCertChain, encodedKey)

	// Test with useIntermediateCA disabled (default)
	config := Config{UseIntermediateCA: false}
	bundle, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err != nil {
		t.Fatalf("Failed to extract TLS bundle: %v", err)
	}

	// Verify the CA data is from ca.crt field
	if !bytes.Equal(bundle.CAData, mockRootCA) {
		t.Error("Expected CA data from ca.crt field, got different data")
	}
}

func TestParseCertificateChain(t *testing.T) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		t.Fatalf("Failed to create test certificate chain: %v", err)
	}

	certs, err := parseCertificateChain(certChain)
	if err != nil {
		t.Fatalf("Failed to parse certificate chain: %v", err)
	}

	if len(certs) != 3 {
		t.Errorf("Expected 3 certificates, got %d", len(certs))
	}

	// Verify order: server, intermediate, root
	expectedCNs := []string{"test.example.com", "Test Intermediate CA", "Test Root CA"}
	for i, cert := range certs {
		if cert.Subject.CommonName != expectedCNs[i] {
			t.Errorf("Certificate %d: expected CN '%s', got '%s'", i, expectedCNs[i], cert.Subject.CommonName)
		}
	}
}

func TestCertificateToPEM(t *testing.T) {
	// Create a simple certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
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
		t.Fatalf("Failed to convert certificate to PEM: %v", err)
	}

	// Verify the PEM can be decoded back
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM type 'CERTIFICATE', got '%s'", block.Type)
	}

	decodedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse decoded certificate: %v", err)
	}

	if decodedCert.Subject.CommonName != "Test Certificate" {
		t.Errorf("Expected CN 'Test Certificate', got '%s'", decodedCert.Subject.CommonName)
	}
}

// Additional test cases for edge cases and error handling

func TestExtractIntermediateCA_MalformedCertificate(t *testing.T) {
	// Create a chain with malformed certificate data
	serverPEM := []byte(`-----BEGIN CERTIFICATE-----
MALFORMED_CERTIFICATE_DATA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ALSO_MALFORMED
-----END CERTIFICATE-----`)

	_, err := ExtractIntermediateCAFromCertChain(serverPEM)
	if err == nil {
		t.Error("Expected error for malformed certificate, got nil")
	}

	// The function now validates chain length before parsing, so we get a different error
	expectedErrors := []string{"error parsing certificate", "certificate chain must contain at least"}
	found := false
	for _, expectedError := range expectedErrors {
		if strings.Contains(err.Error(), expectedError) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected error containing one of %v, got '%s'", expectedErrors, err.Error())
	}
}

func TestExtractIntermediateCA_SelfSignedCertificate(t *testing.T) {
	// Create a self-signed certificate (no intermediate)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Self-Signed Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		IsCA:         true,
	}

	certPEM, _ := generateCertificate(template, template, &key.PublicKey, key)

	// Add another unrelated certificate
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Other Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	otherCertPEM, _ := generateCertificate(otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)

	// Combine into chain
	var chainBuffer bytes.Buffer
	chainBuffer.Write(certPEM)
	chainBuffer.Write(otherCertPEM)

	_, err := ExtractIntermediateCAFromCertChain(chainBuffer.Bytes())
	if err == nil {
		t.Error("Expected error for self-signed certificate with no valid issuer, got nil")
	}

	expectedError := "could not find intermediate CA"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestExtractTLSBundle_MissingSecretFields(t *testing.T) {
	// Test with missing tls.crt field
	secretData := `{"data": {"ca.crt": "Y2EtZGF0YQ==", "tls.key": "a2V5LWRhdGE="}}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err == nil {
		t.Error("Expected error for missing tls.crt field, got nil")
	}

	expectedError := "TLS certificate or key not found in secret data"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestExtractTLSBundle_InvalidBase64(t *testing.T) {
	// Test with invalid base64 data
	secretData := `{"data": {"ca.crt": "invalid-base64!", "tls.crt": "Y2VydC1kYXRh", "tls.key": "a2V5LWRhdGE="}}`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err == nil {
		t.Error("Expected error for invalid base64 data, got nil")
	}
}

func TestExtractTLSBundle_InvalidJSON(t *testing.T) {
	// Test with invalid JSON
	secretData := `{"data": {malformed json`

	config := Config{UseIntermediateCA: false}
	_, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestExtractTLSBundle_NoCA(t *testing.T) {
	// Test when no ca.crt is present in secret
	certChain, err := createTestCertificateChain()
	if err != nil {
		t.Fatalf("Failed to create test certificate chain: %v", err)
	}

	encodedCertChain := base64.StdEncoding.EncodeToString(certChain)
	encodedKey := base64.StdEncoding.EncodeToString([]byte("mock-private-key"))

	// Secret without ca.crt
	secretData := fmt.Sprintf(`{"data": {"tls.crt": "%s", "tls.key": "%s"}}`,
		encodedCertChain, encodedKey)

	// Test with useIntermediateCA enabled (should extract from chain)
	config := Config{UseIntermediateCA: true}
	bundle, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err != nil {
		t.Fatalf("Failed to extract TLS bundle: %v", err)
	}

	// Should have intermediate CA from chain
	if len(bundle.CAData) == 0 {
		t.Error("Expected CA data from certificate chain, got empty")
	}

	// Test with useIntermediateCA disabled (should set empty CA)
	config = Config{UseIntermediateCA: false}
	bundle, err = ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err != nil {
		t.Fatalf("Failed to extract TLS bundle: %v", err)
	}

	// Should have empty CA data
	if len(bundle.CAData) != 0 {
		t.Error("Expected empty CA data, got data")
	}
}

func TestExtractTLSBundle_IntermediateCAFallback(t *testing.T) {
	// Test fallback to ca.crt when intermediate extraction fails
	invalidCertChain := []byte("invalid certificate data")
	encodedInvalidChain := base64.StdEncoding.EncodeToString(invalidCertChain)

	mockRootCA := []byte("fallback-root-ca-data")
	encodedCA := base64.StdEncoding.EncodeToString(mockRootCA)
	encodedKey := base64.StdEncoding.EncodeToString([]byte("mock-private-key"))

	secretData := fmt.Sprintf(`{"data": {"ca.crt": "%s", "tls.crt": "%s", "tls.key": "%s"}}`,
		encodedCA, encodedInvalidChain, encodedKey)

	// Test with useIntermediateCA enabled but fallback should occur
	config := Config{UseIntermediateCA: true}
	bundle, err := ExtractTLSBundleFromSecret([]byte(secretData), config)
	if err != nil {
		t.Fatalf("Expected successful fallback, got error: %v", err)
	}

	// Should have fallen back to ca.crt
	if !bytes.Equal(bundle.CAData, mockRootCA) {
		t.Error("Expected fallback to ca.crt data")
	}
}

// Benchmark tests for performance analysis

func BenchmarkExtractIntermediateCA(b *testing.B) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		b.Fatalf("Failed to create test certificate chain: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExtractIntermediateCAFromCertChain(certChain)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkParseCertificateChain(b *testing.B) {
	certChain, err := createTestCertificateChain()
	if err != nil {
		b.Fatalf("Failed to create test certificate chain: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseCertificateChain(certChain)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// Additional test for config loading

func TestLoadConfigFromFile(t *testing.T) {
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test-config.yaml")

	configContent := `
namespace: test-namespace
secretName: test-secret
localCAFile: /tmp/ca.pem
localCertFile: /tmp/cert.pem
localKeyFile: /tmp/key.pem
observability:
  enableMetrics: true
  logLevel: debug
  tracingEndpoint: http://localhost:4318
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Namespace != "test-namespace" {
		t.Errorf("Expected namespace 'test-namespace', got '%s'", config.Namespace)
	}

	if !config.Observability.EnableMetrics {
		t.Error("Expected metrics enabled")
	}

	if config.Observability.LogLevel != "debug" {
		t.Errorf("Expected log level 'debug', got '%s'", config.Observability.LogLevel)
	}

	if config.Observability.TracingEndpoint != "http://localhost:4318" {
		t.Errorf("Expected tracing endpoint 'http://localhost:4318', got '%s'", config.Observability.TracingEndpoint)
	}
}
