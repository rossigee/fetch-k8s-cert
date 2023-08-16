package main

import (
	"bytes"
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
	LocalFilePath       string `yaml:"localFilePath"`
	ReloadCommand       string `yaml:"reloadCommand"`
	CACertFilePath      string `yaml:"caCertFilePath"`
	SkipTLSVerification bool   `yaml:"skipTLSVerification"`
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

func getTLSCertData(config Config) ([]byte, error) {
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

	certData, keyData, err := extractCertKeyFromSecret(secretData)
	if err != nil {
		return nil, err
	}

	pemCert := append(keyData, certData...)

	return pemCert, nil
}

func extractCertKeyFromSecret(secretData []byte) ([]byte, []byte, error) {
	var secret struct {
		Data map[string]string `json:"data"`
	}

	err := json.Unmarshal(secretData, &secret)
	if err != nil {
		return nil, nil, err
	}

	certData, foundCert := secret.Data["tls.crt"]
	keyData, foundKey := secret.Data["tls.key"]
	if !foundCert || !foundKey {
		return nil, nil, fmt.Errorf("TLS certificate or key not found in secret data")
	}

	decodedCert, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, nil, err
	}

	decodedKey, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, nil, err
	}

	return decodedCert, decodedKey, nil
}

func readFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func writeCertToFile(certData []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(certData)
	if err != nil {
		return err
	}

	return nil
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
	certData, err := getTLSCertData(config)
	if err != nil {
		log.Errorf("Error extracting certificate and key: %v", err)
		return
	}

	localCertData, err := readFile(config.LocalFilePath)
	if err != nil && os.IsNotExist(err) {
		// Handle case where local file doesn't exist
		err = writeCertToFile(certData, config.LocalFilePath)
		if err != nil {
			log.Errorf("Error writing cert and key to local file: %v", err)
		}
		return
	} else if err != nil {
		// Handle other error reading local file
		log.Errorf("Error reading local cert file: %v", err)
		return
	}

	if !bytes.Equal(certData, localCertData) {
		// Certificate data has changed, update the file
		err = writeCertToFile(certData, config.LocalFilePath)
		if err != nil {
			log.Errorf("Error writing updated cert and key to local file: %v", err)
			return
		}

		triggerReload(config.ReloadCommand)
	} else {
		log.Info("Certificate and key contents are the same. No action needed.")
	}
}
