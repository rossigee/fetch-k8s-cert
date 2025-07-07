package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/go-yaml/yaml"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type Config struct {
	K8SAPIURL               string `yaml:"k8sAPIURL"`
	K8SCACertFile           string `yaml:"k8sCACertFile"`
	SkipTLSVerification     bool   `yaml:"skipTLSVerification"`
	Token                   string `yaml:"token"`
	Namespace               string `yaml:"namespace"`
	SecretName              string `yaml:"secretName"`
	LocalCAFile             string `yaml:"localCAFile"`
	LocalCertFile           string `yaml:"localCertFile"`
	LocalKeyFile            string `yaml:"localKeyFile"`
	ReloadCommand           string `yaml:"reloadCommand"`
	UseIntermediateCA       bool   `yaml:"useIntermediateCA"`
}

type TLSBundle struct {
	CAData   []byte
	CertData []byte
	KeyData  []byte
}

func loadConfigFromFile(filePath string) (*Config, error) {
	configData, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file from '%s': %v", filePath, err)
	}

	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config data: %v", err)
	}

	return &config, nil
}

func getTLSCertData(config Config) (*TLSBundle, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", config.K8SAPIURL, config.Namespace, config.SecretName)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerification,
		},
	}

	if !config.SkipTLSVerification && config.K8SCACertFile != "" {
		caCert, err := readFile(config.K8SCACertFile)
		if err != nil {
			return nil, fmt.Errorf("error reading CA certificate file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr.TLSClientConfig.RootCAs = caCertPool
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.Token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	secretData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	tlsBundle, err := extractTLSBundleFromSecret(secretData, config)
	if err != nil {
		return nil, err
	}

	return tlsBundle, nil
}

// extractIntermediateCAFromCertChain extracts the intermediate CA certificate
// that directly issued the server certificate from a certificate chain.
// It parses the certificate chain and finds the certificate that signed the
// server certificate (first certificate in the chain).
func extractIntermediateCAFromCertChain(certChainPEM []byte) ([]byte, error) {
	certificates, err := parseCertificateChain(certChainPEM)
	if err != nil {
		return nil, err
	}
	
	if len(certificates) < 2 {
		return nil, fmt.Errorf("certificate chain must contain at least 2 certificates (server + issuer), found %d", len(certificates))
	}
	
	// The server certificate is typically the first one
	serverCert := certificates[0]
	log.Infof("Server certificate subject: %s", serverCert.Subject.CommonName)
	
	// Find the certificate that issued the server certificate
	for i, cert := range certificates[1:] {
		if err := serverCert.CheckSignatureFrom(cert); err == nil {
			// This is the direct issuer (intermediate CA)
			log.Infof("Found intermediate CA at position %d: %s", i+1, cert.Subject.CommonName)
			return certificateToPEM(cert)
		}
	}
	
	return nil, fmt.Errorf("could not find intermediate CA that issued the server certificate")
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
				return nil, fmt.Errorf("error parsing certificate: %v", err)
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

func extractTLSBundleFromSecret(secretData []byte, config Config) (*TLSBundle, error) {
	var secret struct {
		Data map[string]string `json:"data"`
	}

	err := json.Unmarshal(secretData, &secret)
	if err != nil {
		return nil, err
	}

	caData, foundCa := secret.Data["ca.crt"]
	certData, foundCert := secret.Data["tls.crt"]
	keyData, foundKey := secret.Data["tls.key"]
	if !foundCa || !foundCert || !foundKey {
		return nil, fmt.Errorf("TLS certificate or key not found in secret data")
	}

	decodedCert, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, err
	}
	decodedKey, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, err
	}

	var finalCAData []byte
	
	// If useIntermediateCA is enabled, extract the intermediate CA from the certificate chain
	if config.UseIntermediateCA {
		log.Info("Extracting intermediate CA from certificate chain")
		intermediateCA, err := extractIntermediateCAFromCertChain(decodedCert)
		if err != nil {
			log.Warnf("Failed to extract intermediate CA, falling back to ca.crt: %v", err)
			// Fall back to the original ca.crt
			finalCAData, err = base64.StdEncoding.DecodeString(caData)
			if err != nil {
				return nil, err
			}
		} else {
			finalCAData = intermediateCA
		}
	} else {
		// Use the standard ca.crt field
		finalCAData, err = base64.StdEncoding.DecodeString(caData)
		if err != nil {
			return nil, err
		}
	}

	tlsBundle := TLSBundle{
		finalCAData,
		decodedCert,
		decodedKey,
	}
	return &tlsBundle, nil
}

func readFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func writeToFile(data []byte, filePath string, permissions os.FileMode) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, permissions)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func updateFileIfDifferent(filePath string, data []byte, permissions os.FileMode) (bool, error) {
	// Read the current content of the file
	currentData, err := readFile(filePath)
	if err != nil && os.IsNotExist(err) {
		// Handle case where local file doesn't exist
		err = writeToFile(data, filePath, permissions)
		if err != nil {
			log.Errorf("Error writing client certificate to local file: %v", err)
		}
		return false, err
	} else if err != nil {
		// Handle other error reading local file
		log.Errorf("Error reading local client certificate file: %v", err)
		return false, err
	}

	// Compare the current content with the new data
	if bytesEqual(currentData, data) {
		return false, nil // Content matches, no need to update
	}

	// Update the file with the new data
	err = writeToFile(data, filePath, permissions)
	if err != nil {
		return false, err
	}

	return true, nil // Updated the file
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func triggerReload(command string) {
	log.Info("Certificate and key updated. Triggering reload...")
	reloadCmd := exec.Command("sh", "-c", command)
	reloadCmd.Stdout = os.Stdout
	reloadCmd.Stderr = os.Stderr
	if err := reloadCmd.Run(); err != nil {
		log.Errorf("Error triggering reload command: %v", err)
	}
}

func init() {
	// Customize Logrus settings here, if needed
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

func main() {
	// Define command-line flags
	configFilePath := flag.String("f", "", "Path to the configuration file")
	flag.Parse()

	if *configFilePath == "" {
		fmt.Println("Please provide a path to the configuration file using the -f flag.")
		os.Exit(1)
	}

	// Load the configuration from the specified file
	config, err := loadConfigFromFile(*configFilePath)
	if err != nil {
		fmt.Printf("Error loading configuration from file: %v\n", err)
		os.Exit(1)
	}

	// Call the mainWithConfig function with the loaded configuration
	mainWithConfig(*config)
}

func mainWithConfig(config Config) {
	tlsBundle, err := getTLSCertData(config)
	if err != nil {
		log.Errorf("Error retrieving TLS credentials from Kubernetes API: %v", err)
		return
	}

	certPermissions := os.FileMode(0644) // world-readable
	keyPermissions := os.FileMode(0640)  // group-readable

	caChanged, err := updateFileIfDifferent(config.LocalCAFile, tlsBundle.CAData, certPermissions)
	if err != nil {
		log.Errorf("Unable to update local CA file: %v", err)
		return
	}
	certChanged, err := updateFileIfDifferent(config.LocalCertFile, tlsBundle.CertData, certPermissions)
	if err != nil {
		log.Errorf("Unable to update local cert file: %v", err)
		return
	}
	keyChanged, err := updateFileIfDifferent(config.LocalKeyFile, tlsBundle.KeyData, keyPermissions)
	if err != nil {
		log.Errorf("Unable to update local key file: %v", err)
		return
	}

	if caChanged || certChanged || keyChanged {
		log.Info("TLS details updated. Running reload command.")
		triggerReload(config.ReloadCommand)
	}
}
