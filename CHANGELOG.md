# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2025-12-23

### 🔧 Improvements

- **Go Version**: Updated minimum Go version to 1.25.5 for improved performance and security
- **Dependencies**: Updated dependencies for compatibility with Go 1.25.5

---

## [2.0.0] - 2025-07-07

### 🚀 Major Release - Complete Architecture Overhaul

This is a major release with significant architectural improvements, comprehensive observability features, and enhanced error handling. The codebase has been completely refactored for better maintainability and production readiness.

### ✨ New Features

#### Comprehensive Observability
- **Structured Logging**: Configurable JSON/text logging with multiple levels
- **Prometheus Metrics**: 12 comprehensive metrics covering all operations:
  - Certificate fetch operations (attempts, duration, errors)
  - File operations (writes, errors)
  - Reload operations (attempts, errors)  
  - Certificate validation and CA extraction metrics
  - Certificate age and expiry tracking
- **OpenTelemetry Tracing**: Distributed tracing support with OTLP export
- **Health Monitoring**: Built-in health check endpoint (`/health`)
- **Metrics Server**: Embedded Prometheus metrics server on configurable port

#### Enhanced Architecture
- **Modular Design**: Code split into focused modules (`config.go`, `k8s_client.go`, `certificate.go`, `file_manager.go`, `observability.go`)
- **Context Support**: Full context propagation for cancellation and tracing
- **Graceful Shutdown**: Proper signal handling and resource cleanup
- **Version Flag**: `--version` flag to show version information

#### Improved Certificate Handling
- **Enhanced Error Messages**: More descriptive error messages with context
- **Certificate Information Extraction**: Automatic parsing of certificate details for metrics
- **Directory Creation**: Automatic creation of parent directories for certificate files
- **Better Validation**: Enhanced certificate chain validation and error handling

#### Configuration Enhancements
- **Observability Config**: New `observability` section for comprehensive monitoring configuration
- **Default Values**: Sensible defaults for all observability settings
- **Example Configuration**: Complete example configuration file with all options

### 🔧 Improvements

#### Code Quality
- **Linting**: golangci-lint integration with comprehensive rule set
- **Security Scanning**: gosec integration for vulnerability detection
- **Test Coverage**: Enhanced test suite with coverage reporting
- **Benchmark Tests**: Performance benchmarks for certificate operations

#### CI/CD Enhancements  
- **Enhanced Workflows**: Improved GitHub Actions with security scanning
- **Dynamic Versioning**: Automatic version extraction from git tags
- **Multi-Platform**: Support for Linux amd64/arm64 builds
- **Code Coverage**: Automated coverage reporting via Codecov

#### Docker Improvements
- **Security**: Non-root user execution
- **Multi-Stage**: Optimized multi-stage builds
- **Version Tags**: Proper semantic versioning for container images

### 🐛 Bug Fixes
- **Error Handling**: Improved error propagation and context
- **Resource Management**: Proper cleanup of HTTP connections and file handles
- **Test Reliability**: Fixed flaky tests and improved test isolation
- **Memory Management**: Better memory usage patterns

### 🔄 Breaking Changes
- **Configuration Structure**: New `observability` section in YAML configuration
- **Function Names**: Internal function names changed (affects custom integrations)
- **Import Paths**: Internal package structure reorganized
- **Minimum Go Version**: Requires Go 1.25.5+

### 📊 Metrics Available

The new metrics system provides comprehensive operational visibility:

```
# Certificate Operations
fetch_k8s_cert_fetch_attempts_total{namespace, secret, status}
fetch_k8s_cert_fetch_duration_seconds{namespace, secret, status}
fetch_k8s_cert_fetch_errors_total{namespace, secret, error_type}
fetch_k8s_cert_certificate_age_seconds{namespace, secret}
fetch_k8s_cert_certificate_expiry_seconds{namespace, secret}

# File Operations  
fetch_k8s_cert_file_writes_total{file_type, status}
fetch_k8s_cert_file_write_errors_total{file_type, error_type}

# Service Operations
fetch_k8s_cert_reload_attempts_total{status}
fetch_k8s_cert_reload_errors_total{error_type}

# Certificate Processing
fetch_k8s_cert_validation_total{validation_type, status}
fetch_k8s_cert_ca_extractions_total{extraction_type, status}
fetch_k8s_cert_ca_extraction_errors_total{error_type}
```

### 🚦 OpenTelemetry Tracing

Distributed tracing spans cover:
- `k8s.get_tls_bundle` - Kubernetes API operations
- `certificate.extract_intermediate_ca` - Certificate processing
- `file_manager.update_certificate_files` - File operations
- `file_manager.trigger_reload` - Service reload operations

### 📈 Performance
- **Reduced Memory Usage**: Optimized certificate parsing and handling
- **Faster Startup**: Improved initialization sequence
- **Better Concurrency**: Context-aware operations with proper cancellation
- **Efficient Metrics**: Low-overhead metrics collection

### 🔧 Migration Guide

To upgrade from v1.x to v2.0.0:

1. **Update Configuration**: Add optional `observability` section to your config file
2. **Review Logs**: New structured logging format may require log parser updates
3. **Monitor Metrics**: Set up Prometheus scraping if metrics are enabled
4. **Check Dependencies**: Ensure Go 1.24+ is available for building from source

### 📦 Dependencies
- Added: Prometheus client library
- Added: OpenTelemetry SDK and exporters
- Updated: Various security and performance improvements

---

## [1.3.5] - Previous Release

### Features
- Intermediate CA extraction functionality
- Comprehensive test suite
- Docker multi-arch support
- GitHub Actions CI/CD

### Bug Fixes
- TLS certificate validation improvements
- Error handling enhancements
- Test stability improvements