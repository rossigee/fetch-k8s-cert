package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// TLSBundle represents a complete TLS certificate bundle
type TLSBundle struct {
	CAData   []byte
	CertData []byte
	KeyData  []byte
}

// ExtractTLSBundleFromSecret extracts TLS certificate data from a Kubernetes secret
func ExtractTLSBundleFromSecret(secretData []byte, config Config) (*TLSBundle, error) {
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
	if !foundCa || !foundCert || !foundKey {
		return nil, fmt.Errorf("TLS certificate or key not found in secret data")
	}

	decodedCert, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate data: %w", err)
	}
	
	decodedKey, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key data: %w", err)
	}

	var finalCAData []byte
	
	// If useIntermediateCA is enabled, extract the intermediate CA from the certificate chain
	if config.UseIntermediateCA {
		if obs != nil && obs.logger != nil {
			obs.logger.Info("Extracting intermediate CA from certificate chain")
		}
		
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordCAExtraction("intermediate", "attempt")
		}
		
		intermediateCA, err := ExtractIntermediateCAFromCertChain(decodedCert)
		if err != nil {
			if obs != nil && obs.logger != nil {
				obs.logger.WithError(err).Warn("Failed to extract intermediate CA, falling back to ca.crt")
			}
			if obs != nil && obs.metrics != nil {
				obs.metrics.RecordCAExtractionError("intermediate_extraction")
				obs.metrics.RecordCAExtraction("fallback", "success")
			}
			
			// Fall back to the original ca.crt
			finalCAData, err = base64.StdEncoding.DecodeString(caData)
			if err != nil {
				return nil, fmt.Errorf("failed to decode CA data: %w", err)
			}
		} else {
			finalCAData = intermediateCA
			if obs != nil && obs.metrics != nil {
				obs.metrics.RecordCAExtraction("intermediate", "success")
			}
		}
	} else {
		// Use the standard ca.crt field
		finalCAData, err = base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CA data: %w", err)
		}
		if obs != nil && obs.metrics != nil {
			obs.metrics.RecordCAExtraction("standard", "success")
		}
	}

	tlsBundle := &TLSBundle{
		CAData:   finalCAData,
		CertData: decodedCert,
		KeyData:  decodedKey,
	}
	
	// Extract certificate information for metrics
	if obs != nil && obs.metrics != nil {
		if certInfo, err := parseCertificateInfo(decodedCert); err == nil {
			namespace := config.Namespace
			secret := config.SecretName
			
			now := time.Now()
			age := now.Sub(certInfo.NotBefore)
			timeToExpiry := certInfo.NotAfter.Sub(now)
			
			obs.metrics.SetCertificateAge(namespace, secret, age)
			obs.metrics.SetCertificateExpiry(namespace, secret, timeToExpiry)
			
			if obs.logger != nil {
				obs.logger.WithFields(map[string]interface{}{
					"subject":     certInfo.Subject.CommonName,
					"issuer":      certInfo.Issuer.CommonName,
					"not_before":  certInfo.NotBefore,
					"not_after":   certInfo.NotAfter,
					"age_days":    int(age.Hours() / 24),
					"expires_in_days": int(timeToExpiry.Hours() / 24),
				}).Info("Certificate information extracted")
			}
		}
	}
	
	return tlsBundle, nil
}

// ExtractIntermediateCAFromCertChain extracts the intermediate CA certificate
// that directly issued the server certificate from a certificate chain.
func ExtractIntermediateCAFromCertChain(certChainPEM []byte) ([]byte, error) {
	var span trace.Span
	if obs != nil && obs.tracer != nil {
		_, span = obs.tracer.Start(nil, "certificate.extract_intermediate_ca")
		defer span.End()
	}
	
	certificates, err := parseCertificateChain(certChainPEM)
	if err != nil {
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}
	
	if len(certificates) < 2 {
		err := fmt.Errorf("certificate chain must contain at least 2 certificates (server + issuer), found %d", len(certificates))
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}
	
	// The server certificate is typically the first one
	serverCert := certificates[0]
	if obs != nil && obs.logger != nil {
		obs.logger.WithField("subject", serverCert.Subject.CommonName).Info("Server certificate subject")
	}
	
	// Find the certificate that issued the server certificate
	for i, cert := range certificates[1:] {
		if err := serverCert.CheckSignatureFrom(cert); err == nil {
			// This is the direct issuer (intermediate CA)
			if obs != nil && obs.logger != nil {
				obs.logger.WithFields(map[string]interface{}{
					"position": i + 1,
					"subject":  cert.Subject.CommonName,
				}).Info("Found intermediate CA")
			}
			
			if span != nil {
				span.SetAttributes(
					attribute.String("intermediate_ca_subject", cert.Subject.CommonName),
					attribute.Int("chain_position", i+1),
				)
			}
			
			return certificateToPEM(cert)
		}
	}
	
	err = fmt.Errorf("could not find intermediate CA that issued the server certificate")
	if span != nil {
		span.RecordError(err)
	}
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