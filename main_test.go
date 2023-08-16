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
	testCert := []byte("base64-encoded-cert\n")
	encodedCert := base64.StdEncoding.EncodeToString(testCert)
	testKey := []byte("base64-encoded-key\n")
	encodedKey := base64.StdEncoding.EncodeToString(testKey)
	requestBody := fmt.Sprintf(`{"data": {"tls.crt": "%s", "tls.key": "%s"}}`, encodedCert, encodedKey)
	expectedCertData := append(testKey, testCert...)

	runTestWithConfig(t, requestBody, func(config Config) {
		// Modify the config to intentionally cause a failure
		config.LocalFilePath = "nonexistent-file.pem"

		mainWithConfig(config)

		certFile, err := os.Open(config.LocalFilePath)
		if err != nil {
			t.Fatalf("Failed to open certificate file: %v", err)
		}
		defer certFile.Close()

		var certData bytes.Buffer
		_, err = io.Copy(&certData, certFile)
		if err != nil {
			t.Fatalf("Failed to read certificate data: %v", err)
		}

		if !bytes.Equal(certData.Bytes(), expectedCertData) {
			t.Errorf("Certificate data does not match expected")
		}
	})
}

func TestMainFunction_Failure(t *testing.T) {
	hook := &TestHook{}
	log.AddHook(hook)

	testCert := []byte("base64-encoded-cert\n")
	testKey := []byte("base64-encoded-key\n")
	requestBody := fmt.Sprintf(`{"data": {"tls.crt": "%s", "tls.key": "%s"}}`, testCert, testKey)

	runTestWithConfig(t, requestBody, func(config Config) {
		mainWithConfig(config)

		// Check if the expected error message is logged
		if !containsLogMessage(hook.Messages, "Error extracting certificate and key: invalid character '\\n' in string literal") {
			t.Errorf("Expected error message not found in logs")
		}
	})
}

func TestMainFunction_InvalidConfig(t *testing.T) {
	hook := &TestHook{}
	log.AddHook(hook)

	testCert := []byte("base64-encoded-cert\n")
	encodedCert := base64.StdEncoding.EncodeToString(testCert)
	testKey := []byte("base64-encoded-key\n")
	encodedKey := base64.StdEncoding.EncodeToString(testKey)
	requestBody := fmt.Sprintf(`{"data": {"tls.crt": "%s", "tls.key": "%s"}}`, encodedCert, encodedKey)

	runTestWithConfig(t, requestBody, func(config Config) {
		// Modify the config to use an invalid token
		config.LocalFilePath = "/etc/shadow"

		mainWithConfig(config)

		// Check if the expected error message is logged
		if !containsLogMessage(hook.Messages, "Error reading local cert file: open /etc/shadow: permission denied") {
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

	certFilePath := filepath.Join(tempDir, "test-cert.pem")

	testConfig := Config{
		K8SAPIURL:     mockServer.URL,
		Token:         base64.StdEncoding.EncodeToString([]byte("test-token")),
		Namespace:     "test-namespace",
		CertName:      "test-cert-name",
		LocalFilePath: certFilePath,
		ReloadCommand: "echo test-reload",
	}

	testFunc(testConfig)
}
