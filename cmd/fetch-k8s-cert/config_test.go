package main

import (
	"os"
	"testing"
)

const testSecretToken = "my-secret-token"

func TestResolveEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		envVars     map[string]string
		expected    string
		expectError bool
	}{
		{
			name:     "no variables",
			input:    "literal-token-value",
			expected: "literal-token-value",
		},
		{
			name:     "resolve ${VAR} format",
			input:    "${TEST_TOKEN}",
			envVars:  map[string]string{"TEST_TOKEN": testSecretToken},
			expected: testSecretToken,
		},
		{
			name:     "resolve $VAR format",
			input:    "$TEST_TOKEN",
			envVars:  map[string]string{"TEST_TOKEN": testSecretToken},
			expected: testSecretToken,
		},
		{
			name:  "resolve multiple variables",
			input: "${TOKEN1}:${TOKEN2}",
			envVars: map[string]string{
				"TOKEN1": "part1",
				"TOKEN2": "part2",
			},
			expected: "part1:part2",
		},
		{
			name:        "unresolved variable",
			input:       "${MISSING_VAR}",
			expectError: true,
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "mixed text and variables",
			input:    "Bearer ${AUTH_TOKEN}",
			envVars:  map[string]string{"AUTH_TOKEN": "xyz123"},
			expected: "Bearer xyz123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			result, err := resolveEnvVars(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestLoadConfigFromFileWithEnvVars(t *testing.T) {
	tempDir := t.TempDir()
	configFile := tempDir + "/test-config.yaml"

	// Set environment variable for the test
	testToken := "test-token-from-env-12345"
	t.Setenv("K8S_SA_TOKEN", testToken)

	configContent := `k8sAPIURL: https://kubernetes.example.com:6443
namespace: test-namespace
secretName: test-secret
token: "${K8S_SA_TOKEN}"
localCAFile: /tmp/ca.pem
localCertFile: /tmp/cert.pem
localKeyFile: /tmp/key.pem
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Token != testToken {
		t.Errorf("got token %q, expected %q", config.Token, testToken)
	}
}

func TestLoadConfigFromFileWithLiteralToken(t *testing.T) {
	tempDir := t.TempDir()
	configFile := tempDir + "/test-config.yaml"

	literalToken := "eyJhbGciOiJFUzM4NCIsImtpZCI6ImJMdjBzVUxreHF6cW95aTR3WjBzMG4xYzV5cEJuSHlpbllZTWRRSGJaWUUifQ"

	configContent := `k8sAPIURL: https://kubernetes.example.com:6443
namespace: test-namespace
secretName: test-secret
token: "` + literalToken + `"
localCAFile: /tmp/ca.pem
localCertFile: /tmp/cert.pem
localKeyFile: /tmp/key.pem
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	config, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Token != literalToken {
		t.Errorf("got token %q, expected %q", config.Token, literalToken)
	}
}
