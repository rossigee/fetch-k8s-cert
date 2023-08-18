package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	K8SAPIURL           string `yaml:"k8sAPIURL"`
	Token               string `yaml:"token"`
	Namespace           string `yaml:"namespace"`
	CertName            string `yaml:"certName"`
	LocalCAFile         string `yaml:"localCAFile"`
	LocalCertFile       string `yaml:"localCertFile"`
	LocalKeyFile        string `yaml:"localKeyFile"`
	ReloadCommand       string `yaml:"reloadCommand"`
	CACertFilePath      string `yaml:"caCertFilePath"`
	SkipTLSVerification bool   `yaml:"skipTLSVerification"`
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
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", config.K8SAPIURL, config.Namespace, config.CertName)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerification,
		},
	}

	if !config.SkipTLSVerification && config.CACertFilePath != "" {
		caCert, err := readFile(config.CACertFilePath)
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

	tlsBundle, err := extractTLSBundleFromSecret(secretData)
	if err != nil {
		return nil, err
	}

	return tlsBundle, nil
}

func extractTLSBundleFromSecret(secretData []byte) (*TLSBundle, error) {
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

	decodedCA, err := base64.StdEncoding.DecodeString(caData)
	if err != nil {
		return nil, err
	}
	decodedCert, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, err
	}
	decodedKey, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, err
	}

	tlsBundle := TLSBundle{
		decodedCA,
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
