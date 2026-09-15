package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// K8sClient handles communication with the Kubernetes API
type K8sClient struct {
	client      *http.Client // ordinary requests
	watchClient *http.Client // long-lived watch streams (no total timeout)
	config      Config
	logger      *logrus.Logger
	metrics     *Metrics
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
		TLSClientConfig:      tlsConfig,
		DisableKeepAlives:    false,
		IdleConnTimeout:      90 * time.Second,
		MaxIdleConnsPerHost:  10,
		MaxConnsPerHost:      0, // unlimited
	}

	// Enable TCP keep-alive for long-lived watch connections (fixes QNAP network timeouts)
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext

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

	// Watch streams stay open for an extended period, so they must not be
	// subject to the total request timeout used for ordinary requests.
	watchClient := &http.Client{
		Transport: tr,
	}

	return &K8sClient{
		client:      client,
		watchClient: watchClient,
		config:      config,
		logger:      logger,
		metrics:     metrics,
	}, nil
}

// GetTLSBundle fetches the TLS certificate bundle from Kubernetes
func (k *K8sClient) GetTLSBundle(ctx context.Context) (*TLSBundle, error) {
	tlsBundle, _, err := k.GetTLSBundleWithRV(ctx)
	return tlsBundle, err
}

// GetTLSBundleWithRV fetches the TLS certificate bundle from Kubernetes and
// also returns the resourceVersion of the Secret that was read, so callers can
// start a watch from a consistent point.
func (k *K8sClient) GetTLSBundleWithRV(ctx context.Context) (*TLSBundle, string, error) {
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
		return nil, "", fmt.Errorf("failed to create request: %w", err)
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
					"status":  statusCode, //nolint:goconst
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
		return nil, "", fmt.Errorf("failed to make request: %w", err)
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
		return nil, "", err
	}

	secretData, err := io.ReadAll(resp.Body)
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "response_read")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	resourceVersion := secretResourceVersion(secretData)

	tlsBundle, err := ExtractTLSBundleFromSecret(secretData, k.config, k.logger, k.metrics)
	if err != nil {
		if k.metrics != nil {
			k.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "bundle_extraction")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, resourceVersion, fmt.Errorf("failed to extract TLS bundle: %w", err)
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
			"namespace": k.config.Namespace,  //nolint:goconst
			"secret":    k.config.SecretName, //nolint:goconst
			"duration":  duration,            //nolint:goconst
		}).Info("Successfully fetched TLS bundle from Kubernetes")
	}

	return tlsBundle, resourceVersion, nil
}

// WatchSecret opens a long-lived Kubernetes watch on the configured Secret.
// It returns the response body, which the caller streams until it closes.
func (k *K8sClient) WatchSecret(ctx context.Context, resourceVersion string) (io.ReadCloser, error) {
	u, err := url.Parse(fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		k.config.K8SAPIURL, k.config.Namespace, k.config.SecretName))
	if err != nil {
		return nil, fmt.Errorf("failed to parse watch URL: %w", err)
	}
	query := u.Query()
	query.Add("watch", "true")
	query.Add("allowWatchBookmarks", "true")
	if resourceVersion != "" {
		query.Add("resourceVersion", resourceVersion)
	}
	query.Add("fieldSelector", "metadata.name="+k.config.SecretName)
	u.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create watch request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", k.config.Token))

	resp, err := k.watchClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start watch: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		// #nosec G110 // bounded read of the error response
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("watch failed with status %s (error reading response: %v)", resp.Status, readErr)
		}
		return nil, fmt.Errorf("watch failed with status %s: %s", resp.Status, truncateString(body))
	}

	return resp.Body, nil
}

// secretResourceVersion extracts the resourceVersion from a Secret API object.
func secretResourceVersion(secretJSON []byte) string {
	var secret struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(secretJSON, &secret); err != nil {
		return ""
	}
	return secret.Metadata.ResourceVersion
}

// truncateString limits the length of a string for safe logging.
func truncateString(s []byte) string {
	if len(s) > 4096 {
		return fmt.Sprintf("%s...", string(s[:4096]))
	}
	return string(s)
}
