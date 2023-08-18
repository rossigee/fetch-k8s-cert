package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
		mainWithConfig(config)

		caFile, err := os.Open(config.LocalCAFile)
		if err != nil {
			t.Fatalf("Failed to open CA certificate file: %v", err)
		}
		defer caFile.Close()
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
		mainWithConfig(config)

		// Check if the expected error message is logged
		if !containsLogMessage(hook.Messages, "Error retrieving TLS credentials from Kubernetes API: invalid character '\\n' in string literal") {
			t.Errorf("Expected error message not found in logs")
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
		// Modify the config to use an invalid token
		config.LocalCAFile = "/etc/shadow"

		mainWithConfig(config)

		// Check if the expected error message is logged
		if !containsLogMessage(hook.Messages, "Unable to update local CA file: open /etc/shadow: permission denied") {
			t.Errorf("Expected error message not found in logs")
		}
	})
}

func setupTempDir() string {
	tempDir := os.TempDir()
	testDir := filepath.Join(tempDir, "test-fetch-k8s-cert", strconv.FormatInt(time.Now().UnixNano(), 10))
	err := os.MkdirAll(testDir, 0755)
	if err != nil {
		panic(fmt.Sprintf("Error creating temporary directory: %v", err))
	}
	return testDir
}

func createMockServer(statusCode int, responseBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprintln(w, responseBody)
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
	tempDir := setupTempDir()
	defer os.RemoveAll(tempDir)

	mockServer := createMockServer(http.StatusOK, requestBody)
	defer mockServer.Close()

	caFilePath := filepath.Join(tempDir, "test-ca.pem")
	certFilePath := filepath.Join(tempDir, "test-cert.pem")
	keyFilePath := filepath.Join(tempDir, "test-key.pem")

	testConfig := Config{
		K8SAPIURL:     mockServer.URL,
		Token:         base64.StdEncoding.EncodeToString([]byte("test-token")),
		Namespace:     "test-namespace",
		CertName:      "test-cert-name",
		LocalCAFile:   caFilePath,
		LocalCertFile: certFilePath,
		LocalKeyFile:  keyFilePath,
		ReloadCommand: "echo test-reload",
	}

	testFunc(testConfig)
}
