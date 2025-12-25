package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// ObservabilityConfig contains configuration for observability features
type ObservabilityConfig struct {
	// Logging configuration
	LogLevel         string `yaml:"logLevel"`         // debug, info, warn, error
	LogFormat        string `yaml:"logFormat"`        // json, text
	LogToFile        bool   `yaml:"logToFile"`        // enable file logging
	LogFile          string `yaml:"logFile"`          // log file path
	EnableStructured bool   `yaml:"enableStructured"` // enable structured logging

	// Metrics configuration
	EnableMetrics  bool   `yaml:"enableMetrics"`  // enable Prometheus metrics
	MetricsPort    int    `yaml:"metricsPort"`    // metrics server port (default 8080)
	MetricsPath    string `yaml:"metricsPath"`    // metrics endpoint path (default /metrics)
	MetricsAddress string `yaml:"metricsAddress"` // metrics bind address (default 0.0.0.0)

	// Tracing configuration
	EnableTracing   bool              `yaml:"enableTracing"`   // enable OpenTelemetry tracing
	TracingEndpoint string            `yaml:"tracingEndpoint"` // OTLP endpoint URL (may include path)
	TracingHeaders  map[string]string `yaml:"tracingHeaders"`  // additional headers for tracing
	TracingSampling float64           `yaml:"tracingSampling"` // sampling ratio (0.0 to 1.0)
}

// Metrics holds Prometheus metrics
type Metrics struct {
	// Operational metrics
	FetchAttempts     *prometheus.CounterVec
	FetchDuration     *prometheus.HistogramVec
	FetchErrors       *prometheus.CounterVec
	CertificateAge    *prometheus.GaugeVec
	CertificateExpiry *prometheus.GaugeVec

	// File operations
	FileWrites      *prometheus.CounterVec
	FileWriteErrors *prometheus.CounterVec
	ReloadAttempts  *prometheus.CounterVec
	ReloadErrors    *prometheus.CounterVec

	// Certificate validation
	CertValidation     *prometheus.CounterVec
	CAExtractions      *prometheus.CounterVec
	CAExtractionErrors *prometheus.CounterVec
}

// ObservabilityManager manages all observability features
type ObservabilityManager struct {
	config         ObservabilityConfig
	logger         *logrus.Logger
	metrics        *Metrics
	tracer         oteltrace.Tracer
	tracerProvider *trace.TracerProvider
	metricsServer  *http.Server
}

// NewObservabilityManager creates a new observability manager
func NewObservabilityManager(config ObservabilityConfig) (*ObservabilityManager, error) {
	om := &ObservabilityManager{
		config: config,
	}

	// Initialize logger
	if err := om.initLogger(); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Initialize metrics if enabled
	if config.EnableMetrics {
		if err := om.initMetrics(); err != nil {
			return nil, fmt.Errorf("failed to initialize metrics: %w", err)
		}
	}

	// Initialize tracing if enabled
	if config.EnableTracing {
		if err := om.initTracing(); err != nil {
			return nil, fmt.Errorf("failed to initialize tracing: %w", err)
		}
	}

	return om, nil
}

// initLogger configures the logger based on configuration
func (om *ObservabilityManager) initLogger() error {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(om.config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set log format
	if om.config.LogFormat == "json" || om.config.EnableStructured {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}

	// Configure output
	if om.config.LogToFile && om.config.LogFile != "" {
		file, err := os.OpenFile(om.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		logger.SetOutput(file)
	}

	om.logger = logger
	return nil
}

// initMetrics initializes Prometheus metrics
func (om *ObservabilityManager) initMetrics() error {
	om.metrics = &Metrics{
		FetchAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_fetch_attempts_total",
				Help: "Total number of certificate fetch attempts",
			},
			[]string{"namespace", "secret", "status"},
		),
		FetchDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "fetch_k8s_cert_fetch_duration_seconds",
				Help:    "Duration of certificate fetch operations",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"namespace", "secret", "status"},
		),
		FetchErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_fetch_errors_total",
				Help: "Total number of certificate fetch errors",
			},
			[]string{"namespace", "secret", "error_type"},
		),
		CertificateAge: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "fetch_k8s_cert_certificate_age_seconds",
				Help: "Age of the current certificate in seconds",
			},
			[]string{"namespace", "secret"},
		),
		CertificateExpiry: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "fetch_k8s_cert_certificate_expiry_seconds",
				Help: "Time until certificate expiry in seconds",
			},
			[]string{"namespace", "secret"},
		),
		FileWrites: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_file_writes_total",
				Help: "Total number of certificate file writes",
			},
			[]string{"file_type", "status"},
		),
		FileWriteErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_file_write_errors_total",
				Help: "Total number of certificate file write errors",
			},
			[]string{"file_type", "error_type"},
		),
		ReloadAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_reload_attempts_total",
				Help: "Total number of service reload attempts",
			},
			[]string{"status"},
		),
		ReloadErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_reload_errors_total",
				Help: "Total number of service reload errors",
			},
			[]string{"error_type"},
		),
		CertValidation: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_validation_total",
				Help: "Total number of certificate validations",
			},
			[]string{"validation_type", "status"},
		),
		CAExtractions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_ca_extractions_total",
				Help: "Total number of CA extractions from certificate chains",
			},
			[]string{"extraction_type", "status"},
		),
		CAExtractionErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "fetch_k8s_cert_ca_extraction_errors_total",
				Help: "Total number of CA extraction errors",
			},
			[]string{"error_type"},
		),
	}

	// Register metrics with Prometheus
	prometheus.MustRegister(
		om.metrics.FetchAttempts,
		om.metrics.FetchDuration,
		om.metrics.FetchErrors,
		om.metrics.CertificateAge,
		om.metrics.CertificateExpiry,
		om.metrics.FileWrites,
		om.metrics.FileWriteErrors,
		om.metrics.ReloadAttempts,
		om.metrics.ReloadErrors,
		om.metrics.CertValidation,
		om.metrics.CAExtractions,
		om.metrics.CAExtractionErrors,
	)

	// Start metrics server
	return om.startMetricsServer()
}

// startMetricsServer starts the Prometheus metrics HTTP server
func (om *ObservabilityManager) startMetricsServer() error {
	address := om.config.MetricsAddress
	if address == "" {
		address = "0.0.0.0"
	}

	port := om.config.MetricsPort
	if port == 0 {
		port = 8080
	}

	path := om.config.MetricsPath
	if path == "" {
		path = "/metrics"
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.Handler())

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		_ = err
	})

	om.metricsServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", address, port),
		Handler: mux,
	}

	go func() {
		if err := om.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			om.logger.WithError(err).Error("Metrics server failed")
		}
	}()

	om.logger.WithFields(logrus.Fields{
		"address": address,
		"port":    port,
		"path":    path,
	}).Info("Started metrics server")

	return nil
}

// initTracing initializes OpenTelemetry tracing
func (om *ObservabilityManager) initTracing() error {
	ctx := context.Background()

	// Configure resource
	serviceName := "fetch-k8s-cert"
	serviceVersion := version // Use the global version variable

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Configure exporter
	endpoint := om.config.TracingEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:4318" // Default OTLP HTTP endpoint
	}

	// Strip /v1/traces from endpoint if present to avoid double path
	if strings.HasSuffix(endpoint, "/v1/traces") {
		om.logger.Warn("Tracing endpoint includes /v1/traces path; stripping it to avoid double path")
		endpoint = strings.TrimSuffix(endpoint, "/v1/traces")
	}

	exporterOptions := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Use HTTPS in production
	}

	// Add custom headers if provided
	if len(om.config.TracingHeaders) > 0 {
		exporterOptions = append(exporterOptions, otlptracehttp.WithHeaders(om.config.TracingHeaders))
	}

	exporter, err := otlptracehttp.New(ctx, exporterOptions...)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Configure sampling
	sampling := om.config.TracingSampling
	if sampling <= 0 || sampling > 1 {
		sampling = 1.0 // Default to 100% sampling
	}

	// Create tracer provider
	om.tracerProvider = trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithBatcher(exporter),
		trace.WithSampler(trace.TraceIDRatioBased(sampling)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(om.tracerProvider)

	// Create tracer
	om.tracer = otel.Tracer("fetch-k8s-cert")

	om.logger.WithFields(logrus.Fields{
		"endpoint": endpoint,
		"sampling": sampling,
	}).Info("Initialized OpenTelemetry tracing")

	return nil
}

// Logger returns the configured logger
func (om *ObservabilityManager) Logger() *logrus.Logger {
	return om.logger
}

// Metrics returns the metrics instance
func (om *ObservabilityManager) Metrics() *Metrics {
	return om.metrics
}

// Tracer returns the configured tracer
func (om *ObservabilityManager) Tracer() oteltrace.Tracer {
	return om.tracer
}

// Shutdown gracefully shuts down all observability components
func (om *ObservabilityManager) Shutdown(ctx context.Context) error {
	var errors []error

	// Shutdown metrics server
	if om.metricsServer != nil {
		if err := om.metricsServer.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("metrics server shutdown: %w", err))
		}
	}

	// Shutdown tracer provider
	if om.tracerProvider != nil {
		if err := om.tracerProvider.Shutdown(ctx); err != nil {
			errors = append(errors, fmt.Errorf("tracer provider shutdown: %w", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}

// Helper methods for instrumentation

// RecordFetchAttempt records a certificate fetch attempt
func (m *Metrics) RecordFetchAttempt(namespace, secret, status string) {
	if m != nil && m.FetchAttempts != nil {
		m.FetchAttempts.WithLabelValues(namespace, secret, status).Inc()
	}
}

// RecordFetchDuration records the duration of a fetch operation
func (m *Metrics) RecordFetchDuration(namespace, secret, status string, duration time.Duration) {
	if m != nil && m.FetchDuration != nil {
		m.FetchDuration.WithLabelValues(namespace, secret, status).Observe(duration.Seconds())
	}
}

// RecordFetchError records a fetch error
func (m *Metrics) RecordFetchError(namespace, secret, errorType string) {
	if m != nil && m.FetchErrors != nil {
		m.FetchErrors.WithLabelValues(namespace, secret, errorType).Inc()
	}
}

// SetCertificateAge sets the current certificate age
func (m *Metrics) SetCertificateAge(namespace, secret string, age time.Duration) {
	if m != nil && m.CertificateAge != nil {
		m.CertificateAge.WithLabelValues(namespace, secret).Set(age.Seconds())
	}
}

// SetCertificateExpiry sets the time until certificate expiry
func (m *Metrics) SetCertificateExpiry(namespace, secret string, expiry time.Duration) {
	if m != nil && m.CertificateExpiry != nil {
		m.CertificateExpiry.WithLabelValues(namespace, secret).Set(expiry.Seconds())
	}
}

// RecordFileWrite records a file write operation
func (m *Metrics) RecordFileWrite(fileType, status string) {
	if m != nil && m.FileWrites != nil {
		m.FileWrites.WithLabelValues(fileType, status).Inc()
	}
}

// RecordFileWriteError records a file write error
func (m *Metrics) RecordFileWriteError(fileType, errorType string) {
	if m != nil && m.FileWriteErrors != nil {
		m.FileWriteErrors.WithLabelValues(fileType, errorType).Inc()
	}
}

// RecordReloadAttempt records a service reload attempt
func (m *Metrics) RecordReloadAttempt(status string) {
	if m != nil && m.ReloadAttempts != nil {
		m.ReloadAttempts.WithLabelValues(status).Inc()
	}
}

// RecordReloadError records a reload error
func (m *Metrics) RecordReloadError(errorType string) {
	if m != nil && m.ReloadErrors != nil {
		m.ReloadErrors.WithLabelValues(errorType).Inc()
	}
}

// RecordCertValidation records a certificate validation
func (m *Metrics) RecordCertValidation(validationType, status string) {
	if m != nil && m.CertValidation != nil {
		m.CertValidation.WithLabelValues(validationType, status).Inc()
	}
}

// RecordCAExtraction records a CA extraction operation
func (m *Metrics) RecordCAExtraction(extractionType, status string) {
	if m != nil && m.CAExtractions != nil {
		m.CAExtractions.WithLabelValues(extractionType, status).Inc()
	}
}

// RecordCAExtractionError records a CA extraction error
func (m *Metrics) RecordCAExtractionError(errorType string) {
	if m != nil && m.CAExtractionErrors != nil {
		m.CAExtractionErrors.WithLabelValues(errorType).Inc()
	}
}
