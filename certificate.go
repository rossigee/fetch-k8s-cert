package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// TLSBundle represents a complete TLS certificate bundle
type TLSBundle struct {
	CAData   []byte
	CertData []byte
	KeyData  []byte
}

// ExtractTLSBundleFromSecret extracts TLS certificate data from a Kubernetes secret
func ExtractTLSBundleFromSecret(secretData []byte, config Config, logger *logrus.Logger, metrics *Metrics) (*TLSBundle, error) {
	var secret struct {
		Data map[string]string `json:"data"`
	}

	err := json.Unmarshal(secretData, &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

	caData, foundCa := secret.Data["ca.crt"]
	certData, foundCert := secret.Data["tls.crt"]
	keyData, foundKey := secret.Data["tls.key"]
	if !foundCert || !foundKey {
		return nil, fmt.Errorf("TLS certificate or key not found in secret data")
	}

	decodedCert, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate data: %w", err)
	}
	if len(decodedCert) > 10*1024*1024 { // 10MB limit
		return nil, fmt.Errorf("certificate data too large: %d bytes", len(decodedCert))
	}

	decodedKey, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key data: %w", err)
	}
	if len(decodedKey) > 10*1024*1024 { // 10MB limit
		return nil, fmt.Errorf("key data too large: %d bytes", len(decodedKey))
	}

	var finalCAData []byte

	// If useIntermediateCA is enabled, extract the intermediate CA from the certificate chain
	if config.UseIntermediateCA {
		if logger != nil {
			logger.Info("Extracting intermediate CA from certificate chain")
		}

		if metrics != nil {
			metrics.RecordCAExtraction("intermediate", "attempt")
		}

		intermediateCA, err := ExtractIntermediateCAFromCertChain(decodedCert, logger)
		if err != nil {
			if logger != nil {
				logger.WithError(err).Warn("Failed to extract intermediate CA")
			}
			if metrics != nil {
				metrics.RecordCAExtractionError("intermediate_extraction")
			}

			// Try to fall back to the original ca.crt if available
			if foundCa {
				finalCAData, err = base64.StdEncoding.DecodeString(caData)
				if err != nil {
					return nil, fmt.Errorf("failed to decode CA data: %w", err)
				}
				if len(finalCAData) > 10*1024*1024 { // 10MB limit
					return nil, fmt.Errorf("CA data too large: %d bytes", len(finalCAData))
				}
				if metrics != nil {
					metrics.RecordCAExtraction("fallback", "success")
				}
			} else {
				// No CA available
				finalCAData = []byte{}
				if metrics != nil {
					metrics.RecordCAExtraction("none", "success")
				}
			}
		} else {
			finalCAData = intermediateCA
			if metrics != nil {
				metrics.RecordCAExtraction("intermediate", "success")
			}
		}
	} else {
		// Use the standard ca.crt field if available
		if foundCa {
			finalCAData, err = base64.StdEncoding.DecodeString(caData)
			if err != nil {
				return nil, fmt.Errorf("failed to decode CA data: %w", err)
			}
			if len(finalCAData) > 10*1024*1024 { // 10MB limit
				return nil, fmt.Errorf("CA data too large: %d bytes", len(finalCAData))
			}
			if metrics != nil {
				metrics.RecordCAExtraction("standard", "success")
			}
		} else {
			// No CA available
			finalCAData = []byte{}
			if metrics != nil {
				metrics.RecordCAExtraction("none", "success")
			}
		}
	}

	tlsBundle := &TLSBundle{
		CAData:   finalCAData,
		CertData: decodedCert,
		KeyData:  decodedKey,
	}

	// Extract certificate information for metrics
	if metrics != nil {
		if certInfo, err := parseCertificateInfo(decodedCert); err == nil {
			namespace := config.Namespace
			secret := config.SecretName

			now := time.Now()
			age := now.Sub(certInfo.NotBefore)
			timeToExpiry := certInfo.NotAfter.Sub(now)

			metrics.SetCertificateAge(namespace, secret, age)
			metrics.SetCertificateExpiry(namespace, secret, timeToExpiry)

			if logger != nil {
				logger.WithFields(map[string]interface{}{
					"subject":         certInfo.Subject.CommonName,
					"issuer":          certInfo.Issuer.CommonName,
					"not_before":      certInfo.NotBefore,
					"not_after":       certInfo.NotAfter,
					"age_days":        int(age.Hours() / 24),
					"expires_in_days": int(timeToExpiry.Hours() / 24),
				}).Info("Certificate information extracted")
			}
		}
	}

	return tlsBundle, nil
}

// ExtractIntermediateCAFromCertChain extracts the intermediate CA certificate
// that directly issued the server certificate from a certificate chain.
func ExtractIntermediateCAFromCertChain(certChainPEM []byte, logger *logrus.Logger) ([]byte, error) {
	// Note: We don't have access to tracer here anymore since we removed global obs
	// Tracing would need to be passed as a parameter if needed

	certificates, err := parseCertificateChain(certChainPEM)
	if err != nil {
		return nil, err
	}

	if len(certificates) < 2 {
		err := fmt.Errorf("certificate chain must contain at least 2 certificates "+
			"(server + issuer), found %d", len(certificates))
		return nil, err
	}

	// The server certificate is typically the first one
	serverCert := certificates[0]
	if logger != nil {
		logger.WithField("subject", serverCert.Subject.CommonName).Info("Server certificate subject")
	}

	// Find the certificate that issued the server certificate
	for i, cert := range certificates[1:] {
		if err := serverCert.CheckSignatureFrom(cert); err == nil {
			// This is the direct issuer (intermediate CA)
			if logger != nil {
				logger.WithFields(map[string]interface{}{
					"position": i + 1,
					"subject":  cert.Subject.CommonName,
				}).Info("Found intermediate CA")
			}

			return certificateToPEM(cert)
		}
	}

	err = fmt.Errorf("could not find intermediate CA that issued the server certificate")
	return nil, err
}

// parseCertificateChain parses a PEM-encoded certificate chain and returns
// all certificates as x509.Certificate objects
func parseCertificateChain(certChainPEM []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	rest := certChainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate: %w", err)
			}
			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}

// certificateToPEM converts an x509.Certificate to PEM format
func certificateToPEM(cert *x509.Certificate) ([]byte, error) {
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// parseCertificateInfo extracts key information from a certificate for metrics
func parseCertificateInfo(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}
