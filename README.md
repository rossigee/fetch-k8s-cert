# Fetch K8s Certificate v2.1.6

**Enterprise-grade certificate management tool with comprehensive observability.**

A production-ready utility to pull TLS certificates from Kubernetes secrets and write them to disk for consumption by other services. Features include distributed tracing, Prometheus metrics, structured logging, and intermediate CA extraction.

## 🚀 What's New in v2.0.0

- **📊 Comprehensive Observability**: Prometheus metrics, OpenTelemetry tracing, structured logging
- **🏗️ Modular Architecture**: Clean separation of concerns with focused modules
- **🔍 Enhanced Monitoring**: 12 metrics covering all operations, health checks, certificate expiry tracking
- **🔒 Security**: Enhanced error handling, security scanning, non-root container execution
- **⚡ Performance**: Optimized memory usage, context-aware operations, graceful shutdown
- **🧪 Quality**: Comprehensive test suite, linting, benchmarks, 95%+ test coverage

This program is designed to connect to a Kubernetes API, fetch the contents of a TLS Certificate resource and compare it to the existing local copy. If the certificate has been updated on the cluster, the local copy will be replaced and a reload command will be triggered, which may be used to restart any dependent services.

The primary use case for this is for organisations already running K8S clusters to be able to leverage their existing `cert-manager` deployment to manage certificates for services running outside of the cluster too. This may be a better solution for many organisations that would prefer not to deploy more complicated tools (i.e. `certbot`) at towards the edge.

## Kubernetes configuration

Assuming you're using `cert-manager` and have already configured your `Issuer`/`ClusterIssuer` resources. To produce the TLS Secret resources, you would likely just need to create a `Certificate` resource (i.e. in Flux/ArgoCD), and a `ServiceAccount` that can read the resulting TLS `Secret`. For example:

```yaml
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: myservice
spec:
  commonName: service.yourdomain.com
  issuerRef:
    group: cert-manager.io
    kind: ClusterIssuer
    name: vault
  privateKey:
    algorithm: ECDSA
    rotationPolicy: Always
    size: 384
  secretName: service-tls
  usages:
  - key agreement
  - digital signature
  - server auth
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myservice
---
apiVersion: v1
kind: Secret
metadata:
  name: myservice-sa
  annotations:
    kubernetes.io/service-account.name: myservice
type: kubernetes.io/service-account-token
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: myservice
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: myservice
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: myservice
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:serviceaccount:yournamespace:myservice
```

At this point, the `Secret` should be available and ready for the service to check and collect on a regular basis.

You will need the JWT service account token for the next bit, which you can obtain using `kubectl` as follows:

```bash
kubectl -n yournamespace get secret myservice-sa -ojsonpath='{.data.token}' | base64 -d >/tmp/jwt-token
```

Confirm the JWT service account token has access to retrieve the TLS secret:

```bash
kubectl --token=$(cat /tmp/jwt-token) -n yournamespace get secret myservice-sa -ojsonpath='{.data.token}' | base64 -d;echo
```

Next, create a configuration file in YAML format with the following fields:

```yaml
# URL of the Kubernetes API
k8sAPIURL: https://your.cluster.address:6443

# Path to the CA file for the K8S API server
k8sCACertFile: /etc/pki/tls/ca.crt

# Enable to skip TLS verification of the K8S API server
skipTLSVerification: true

# Base64-encoded authentication token
token: jwt_token_from_service_account

# Kubernetes namespace where the certificate is located
namespace: yournamespace

# Name of the secret resource containing the certificate details
secretName: service-tls

# Path to the local TLS files.
localCAFile: /etc/pki/tls/service-ca.pem
localCertFile: /etc/pki/tls/service-cert.pem
localKeyFile: /etc/pki/tls/service-key.pem

# Command to trigger a service reload.
# NOTE: If the service using the certificate knows when the certificate files have been updated and can reload them itself, the `reloadCommand` is largely unnecessary. However, if the service needs to be restarted manually when a new certificate is deployed, the `reloadCommand` could be used to `systemctl restart yourservice`. The `fetch-k8s-cert` tool has been designed to be run as 'non-root', so you may also need to add `sudo` and configure `sudoers` if restarting the service requires elevated privileges, or take other measures if running in a Docker container.
reloadCommand: "echo 'The cert changed.'"

# Extract intermediate CA from certificate chain instead of using ca.crt
# This is useful when the service needs the intermediate CA that actually issued 
# the server certificate, rather than the root CA stored in the secret's ca.crt field.
# Default: false (uses ca.crt field)
useIntermediateCA: false
```

You could run try running this locally...

```bash
./fetch-k8s-cert -f config.yaml
```

Typically, you would be deploying this either as a 'systemd' service or as a Docker container in `docker-compose`.

### Debian Package Installation on Ubuntu

1. **Install the Package**
   ```bash
   sudo apt update
   sudo apt install ./fetch-k8s-cert_2.1.6_amd64.deb
   ```

2. **Configure the Tool**
   - Put your configuration file in place at `/etc/fetch-k8s-cert/config.yaml`.
   - Set appropriate permissions:
     ```bash
     sudo chown root:root /etc/fetch-k8s-cert/config.yaml
     sudo chmod 600 /etc/fetch-k8s-cert/config.yaml
     ```

3. **Run the Service**
   - Enable and start the systemd service:
     ```bash
     sudo systemctl enable fetch-k8s-cert
     sudo systemctl start fetch-k8s-cert
     ```
   - Verify the service is running:
     ```bash
     sudo systemctl status fetch-k8s-cert
     ```

### Docker Compose Setup with Nginx

This setup demonstrates using `fetch-k8s-cert` to renew certificates for an Nginx container.

1. **Create a Docker Compose File**
   Create `docker-compose.yml`:
   ```yaml
   services:
     cert-fetcher:
       image: ghcr.io/rossigee/fetch-k8s-cert:latest
       volumes:
         - ./certs:/etc/ssl/certs
         - ./config:/etc/fetch-k8s-cert
       environment:
         - CONFIG_PATH=/etc/fetch-k8s-cert/config.yaml
       restart: no

     nginx:
       image: nginx:latest
       volumes:
         - ./certs:/etc/nginx/certs:ro
       ports:
         - "443:443"
       depends_on:
         - cert-fetcher
       restart: always
   ```

4. **Nginx/HAProxy Configuration**
   - For Nginx, update `/etc/nginx/nginx.conf` to use the certificates:
     ```nginx
     server {
         listen 443 ssl;
         ssl_certificate /etc/nginx/certs/tls.crt;
         ssl_certificate_key /etc/nginx/certs/tls.key;
         ...
     }
     ```
   - For HAProxy, update `/etc/haproxy/haproxy.cfg`:
     ```haproxy
     frontend https_front
         bind *:443 ssl crt /etc/nginx/certs/tls.pem
         ...
     ```
   - Combine certificate and key for HAProxy:
     ```bash
     cat /etc/ssl/certs/tls.crt /etc/ssl/certs/tls.key > /etc/ssl/certs/tls.pem
     ```

3. **Run Docker Compose**
   ```bash
   docker-compose up -d
   ```

5. **Restart Services**
   - Restart container when certificates are updated:
     ```bash
     docker-compose restart nginx
     ```

## Intermediate CA Extraction

When working with multi-tier PKI setups, you may encounter situations where the CA certificate stored in the Kubernetes secret's `ca.crt` field is the root CA, but your service actually needs the intermediate CA that directly issued the server certificate.

### Problem Scenario

In a typical enterprise PKI setup:
1. **Root CA** issues certificates to **Intermediate CAs**
2. **Intermediate CAs** issue certificates to servers/services
3. Services need the **Intermediate CA** certificate for proper validation
4. However, cert-manager often stores the **Root CA** in the `ca.crt` field

This causes TLS validation errors like:
- "certificate relies on legacy Common Name field, use SANs instead"
- "certificate hasn't got a known issuer"

### Solution: `useIntermediateCA` Option

Enable intermediate CA extraction to automatically find and extract the correct CA certificate:

```yaml
# Enable intermediate CA extraction
useIntermediateCA: true
```

### How It Works

1. **Parses Certificate Chain**: Examines all certificates in the `tls.crt` field
2. **Finds Direct Issuer**: Uses cryptographic signature verification to identify which certificate issued the server certificate
3. **Extracts Intermediate CA**: Returns the intermediate CA certificate in PEM format
4. **Graceful Fallback**: Falls back to `ca.crt` if intermediate extraction fails

### Example Configuration

```yaml
# libvirt TLS configuration with intermediate CA extraction
k8sAPIURL: https://k8s-api.cluster.local:6443
skipTLSVerification: true
token: eyJhbGciOiJSUzI1NiIs...
namespace: vm-hosts
secretName: libvirt-tls
localCAFile: /etc/pki/CA/cacert.pem
localCertFile: /etc/pki/libvirt/servercert.pem
localKeyFile: /etc/pki/libvirt/private/serverkey.pem
reloadCommand: "systemctl restart libvirtd.service"
useIntermediateCA: true
```

### Logging

When intermediate CA extraction is enabled, you'll see detailed logging:

```
time="2025-07-07T13:55:57+07:00" level=info msg="Extracting intermediate CA from certificate chain"
time="2025-07-07T13:55:57+07:00" level=info msg="Server certificate subject: server.example.com"
time="2025-07-07T13:55:57+07:00" level=info msg="Found intermediate CA at position 1: Example Intermediate CA"
```

## Development

### Building from Source

```bash
# Build binary
make build

# Run tests
go test -v

# Run tests with coverage
go test -v -race -coverprofile=coverage.out

# Run linter
golangci-lint run

# Build Docker image
docker build -t fetch-k8s-cert .
```

### Testing

The project includes comprehensive test coverage for all major functionality:

- **Unit Tests**: Core functionality with full mocking
- **Integration Tests**: Certificate chain parsing and validation
- **Edge Case Tests**: Error handling, malformed data, invalid certificates
- **Benchmark Tests**: Performance analysis for certificate operations

Run specific test suites:
```bash
# Run all tests
go test -v

# Run tests with benchmarks
go test -v -bench=.

# Run specific test
go test -v -run TestExtractIntermediateCA
```

### CI/CD

The project uses GitHub Actions for:

- **Code Quality**: golangci-lint for static analysis
- **Security Scanning**: gosec for vulnerability detection  
- **Test Coverage**: Automated coverage reporting via Codecov
- **Multi-Platform Builds**: Linux amd64/arm64 binaries
- **Container Images**: Multi-arch Docker images
- **Release Automation**: Semantic versioning with automated releases

Build status: ![Build](https://github.com/rossigee/fetch-k8s-cert/workflows/Build/badge.svg)

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Ensure your code:
- Passes all tests: `go test -v`
- Passes linting: `golangci-lint run`
- Includes appropriate test coverage
- Follows Go best practices

## Notes
- Ensure the Kubernetes secret contains `tls.crt` and `tls.key` fields (obviously).
- The `cert-fetcher` container should have access to the Kubernetes API (obviously).
- When using `useIntermediateCA: true`, ensure your certificate chain contains both server and intermediate certificates.
- Monitor logs for issues:
  ```bash
  docker-compose logs cert-fetcher
  ```

## License

This project is licensed under the MIT License - see the LICENSE file for details.