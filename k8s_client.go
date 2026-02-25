package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// K8sClient handles communication with the Kubernetes API
type K8sClient struct {
	client  *http.Client
	config  Config
	logger  *logrus.Logger
	metrics *Metrics
}

// NewK8sClient creates a new Kubernetes API client
func NewK8sClient(config Config, logger *logrus.Logger, metrics *Metrics) (*K8sClient, error) {
	var tlsConfig *tls.Config
	if config.SkipTLSVerification {
		tlsConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402
	} else {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if !config.SkipTLSVerification && config.K8SCACertFile != "" {
		// #nosec G304
		caCert, err := readFile(config.K8SCACertFile)
		if err != nil {
			return nil, fmt.Errorf("error reading CA certificate file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}

	timeout := 30 * time.Second // default
	if config.HTTPClientTimeout > 0 {
		timeout = time.Duration(config.HTTPClientTimeout) * time.Second
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	return &K8sClient{
		client:  client,
		config:  config,
		logger:  logger,
		metrics: metrics,
	}, nil
}

// GetTLSBundle fetches the TLS certificate bundle from Kubernetes
func (k *K8sClient) GetTLSBundle(ctx context.Context) (*TLSBundle, error) {
	// Note: We removed global obs, so tracing is disabled for now
	// If tracing is needed, it should be passed as a parameter
	var span trace.Span

	start := time.Now()

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		k.config.K8SAPIURL, k.config.Namespace, k.config.SecretName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "request_creation")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", k.config.Token))

	// Retry logic for transient failures
	var resp *http.Response
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = k.client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			break // Success or client error, don't retry
		}
		if attempt < maxRetries {
			if resp != nil {
				_ = resp.Body.Close() // Ignore close error during retry
			}
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}
			if k.logger != nil {
				k.logger.WithFields(logrus.Fields{
					"attempt": attempt,
					"error":   err,
					"status":  statusCode,
				}).Warn("Request failed, retrying")
			}
			time.Sleep(time.Duration(attempt) * time.Second) // Exponential backoff
		}
	}
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "network")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errorType := "api_error"
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			errorType = "unauthorized"
		case http.StatusForbidden:
			errorType = "forbidden"
		case http.StatusNotFound:
			errorType = "not_found"
		}

		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, errorType)
		}

		err := fmt.Errorf("unexpected response status: %s", resp.Status)
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}

	secretData, err := io.ReadAll(resp.Body)
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "response_read")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	tlsBundle, err := ExtractTLSBundleFromSecret(secretData, k.config, k.logger, k.metrics)
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "bundle_extraction")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to extract TLS bundle: %w", err)
	}

	duration := time.Since(start)

	// Record successful metrics
	if k.metrics != nil {
		k.metrics.RecordFetchAttempt(k.config.Namespace, k.config.SecretName, "success")
		k.metrics.RecordFetchDuration(k.config.Namespace, k.config.SecretName, "success", duration)
	}

	if span != nil {
		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)
	}

	if k.logger != nil {
		k.logger.WithFields(map[string]interface{}{
			"namespace": k.config.Namespace,
			"secret":    k.config.SecretName,
			"duration":  duration,
		}).Info("Successfully fetched TLS bundle from Kubernetes")
	}

	return tlsBundle, nil
}
