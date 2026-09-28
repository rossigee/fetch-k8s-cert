# fetch-k8s-cert

**Enterprise-grade Kubernetes certificate management for external services.**

Fetch TLS certificates from Kubernetes secrets and write them to disk for consumption by services running outside the cluster. Features event-driven watch mode, Prometheus metrics, OpenTelemetry tracing, and structured logging.

## Quick Start

```bash
# Watch a single secret forever
./fetch-k8s-cert -w -f config.yaml

# Watch multiple secrets in one process
./fetch-k8s-cert -w -d /etc/fetch-k8s-cert/conf.d

# One-shot fetch and exit
./fetch-k8s-cert -f config.yaml
```

## Documentation

- **[📖 Full Documentation](docs/README.md)** — Configuration, examples, and detailed usage
- **[📊 Observability Guide](docs/README.md#observability)** — Metrics, logging, and distributed tracing
- **[📝 Changelog](docs/CHANGELOG.md)** — Release history and breaking changes
- **[⚙️ Examples](examples/)** — Configuration examples and systemd setup

## Key Features

- **🎯 Event-Driven Watch Mode** — React to K8s secret changes instantly, not on a schedule
- **📡 Multi-Config Support** — Manage multiple secrets in a single process with `-d <dir>`
- **🔌 Zero-Downtime Reloads** — Compatible with HAProxy Runtime API and systemctl reload
- **📊 Enterprise Observability** — Prometheus metrics, OpenTelemetry tracing, structured logging
- **🔗 Intermediate CA Extraction** — Automatically find and extract the correct CA from certificate chains
- **🛡️ Security First** — Non-root execution, TLS verification required, input validation

## Installation

### Debian/Ubuntu

```bash
sudo apt update
sudo apt install ./fetch-k8s-cert_3.2.0_amd64.deb
```

### Docker

```bash
docker run -v ./config:/etc/fetch-k8s-cert \
           -v ./certs:/etc/ssl/certs \
           ghcr.io/rossigee/fetch-k8s-cert:latest \
           -w -f /etc/fetch-k8s-cert/config.yaml
```

### From Source

```bash
make build
./build/fetch-k8s-cert -f config.yaml
```

## Project Structure

```
fetch-k8s-cert/
├── cmd/fetch-k8s-cert/        Source code
├── docs/                       Documentation
├── examples/                   Configuration examples
├── build/                      Build output
└── ...
```

## License

MIT

---

👉 **[Start here: Full Documentation](docs/README.md)**
