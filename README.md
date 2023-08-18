# Fetch K8s Certificate 

This program is designed to be run on a regulary schedule to poll a K8S cluster for changes to a given TLS certificate resource. Briefly, this tool reads a YAML configuration file, connects to a Kubernetes API using credentials configured, fetches the contents of a TLS Certificate resource, compares it to a local file, and triggers a reload command if the contents have changed.

The primary use case for this tool is to allow `cert-manager` to manage the lifecycle of the certificates on a Kubernetes cluster, but a non-K8S instance can use this tool to retrieve the latest copy of the TLS keypair from cluster and manage it locally. A local process (for example, 'haproxy') can then use the TLS certificate for client or server authentication.

## Basic usage

Build the binary...

```
go build
```

Create a configuration file in YAML format with the following fields:

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
namespace: internal

# Name of the secret resource containing the certificate details
secretName: internal-tls

# Path to the local TLS files.
localCAFile: /etc/pki/tls/internal-ca.pem
localCertFile: /etc/pki/tls/internal-cert.pem
localKeyFile: /etc/pki/tls/internal-key.pem

# Command to trigger a service reload.
reloadCommand: "echo 'The cert changed.'"
```

Run the binary...

```
./fetch-k8s-cert -f config.yaml
```
