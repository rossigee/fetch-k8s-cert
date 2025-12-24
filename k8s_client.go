package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// K8sClient handles communication with the Kubernetes API
type K8sClient struct {
	client *http.Client
	config Config
}

// NewK8sClient creates a new Kubernetes API client
func NewK8sClient(config Config) (*K8sClient, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerification,
		},
	}

	if !config.SkipTLSVerification && config.K8SCACertFile != "" {
		caCert, err := readFile(config.K8SCACertFile)
		if err != nil {
			return nil, fmt.Errorf("error reading CA certificate file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	return &K8sClient{
		client: client,
		config: config,
	}, nil
}

// GetTLSBundle fetches the TLS certificate bundle from Kubernetes
func (k *K8sClient) GetTLSBundle(ctx context.Context) (*TLSBundle, error) {
	var span trace.Span
	if obs != nil && obs.tracer != nil {
		ctx, span = obs.tracer.Start(ctx, "k8s.get_tls_bundle",
			trace.WithAttributes(
				attribute.String("namespace", k.config.Namespace),
				attribute.String("secret", k.config.SecretName),
			),
		)
		defer span.End()
	}

	start := time.Now()

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s",
		k.config.K8SAPIURL, k.config.Namespace, k.config.SecretName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "request_creation")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", k.config.Token))

	resp, err := k.client.Do(req)
	if err != nil {
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "network")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		errorType := "api_error"
		if resp.StatusCode == http.StatusUnauthorized {
			errorType = "unauthorized"
		} else if resp.StatusCode == http.StatusForbidden {
			errorType = "forbidden"
		} else if resp.StatusCode == http.StatusNotFound {
			errorType = "not_found"
		}

		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, errorType)
		}

		err := fmt.Errorf("unexpected response status: %s", resp.Status)
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}

	secretData, err := io.ReadAll(resp.Body)
	if err != nil {
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "response_read")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	tlsBundle, err := ExtractTLSBundleFromSecret(secretData, k.config)
	if err != nil {
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordFetchError(k.config.Namespace, k.config.SecretName, "bundle_extraction")
		}
		if span != nil {
			span.RecordError(err)
		}
		return nil, fmt.Errorf("failed to extract TLS bundle: %w", err)
	}

	duration := time.Since(start)

	// Record successful metrics
	if obs != nil && obs.metrics != nil {
		obs.metrics.RecordFetchAttempt(k.config.Namespace, k.config.SecretName, "success")
		obs.metrics.RecordFetchDuration(k.config.Namespace, k.config.SecretName, "success", duration)
	}

	if span != nil {
		span.SetAttributes(
			attribute.Bool("success", true),
			attribute.Float64("duration_seconds", duration.Seconds()),
		)
	}

	if obs != nil && obs.logger != nil {
		obs.logger.WithFields(map[string]interface{}{
			"namespace": k.config.Namespace,
			"secret":    k.config.SecretName,
			"duration":  duration,
		}).Info("Successfully fetched TLS bundle from Kubernetes")
	}

	return tlsBundle, nil
}
