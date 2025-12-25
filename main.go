package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
)

var (
	version = "2.1.0" // Set by build flags
	log     = logrus.New()
	obs     *ObservabilityManager
)

func main() {
	// Define command-line flags
	configFilePath := flag.String("f", "", "Path to the configuration file")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging (info level)")
	versionFlag := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("fetch-k8s-cert version %s\n", version)
		os.Exit(0)
	}

	if *configFilePath == "" {
		fmt.Println("Please provide a path to the configuration file using the -f flag.")
		fmt.Println("Usage: fetch-k8s-cert -f <config-file> [-v]")
		os.Exit(1)
	}

	// Load the configuration from the specified file
	config, err := LoadConfigFromFile(*configFilePath)
	if err != nil {
		fmt.Printf("Error loading configuration from file: %v\n", err)
		os.Exit(1)
	}

	// Override log level if verbose flag is set
	if *verboseFlag {
		config.Observability.LogLevel = "info"
	}

	// Initialize observability
	obs, err = NewObservabilityManager(config.Observability)
	if err != nil {
		fmt.Printf("Error initializing observability: %v\n", err)
		os.Exit(1)
	}

	// Replace global logger with observability logger
	log = obs.Logger()

	// Set up graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.WithField("signal", sig.String()).Info("Received shutdown signal")
		cancel()
	}()

	// Run the application
	if err := run(ctx, *config); err != nil {
		log.WithError(err).Error("Application failed")
		os.Exit(1)
	}

	// Graceful shutdown
	log.Info("Shutting down...")
	if err := obs.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Error during observability shutdown")
	}
}

// run executes the main application logic
func run(ctx context.Context, config Config) error {
	log.WithFields(logrus.Fields{
		"version":             version,
		"namespace":           config.Namespace,
		"secret":              config.SecretName,
		"k8s_api":             config.K8SAPIURL,
		"use_intermediate_ca": config.UseIntermediateCA,
	}).Info("Starting fetch-k8s-cert")

	// Create Kubernetes client
	k8sClient, err := NewK8sClient(config)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Create file manager
	fileManager := NewFileManager(config)

	// Fetch TLS bundle from Kubernetes
	log.Info("Fetching TLS certificate bundle from Kubernetes")
	tlsBundle, err := k8sClient.GetTLSBundle(ctx)
	if err != nil {
		return fmt.Errorf("failed to get TLS bundle: %w", err)
	}

	// Update local certificate files
	log.Info("Updating local certificate files")
	filesChanged, err := fileManager.UpdateCertificateFiles(ctx, tlsBundle)
	if err != nil {
		return fmt.Errorf("failed to update certificate files: %w", err)
	}

	// Trigger reload if files changed
	if filesChanged {
		log.Info("Certificate files changed, triggering reload")
		if err := fileManager.TriggerReload(ctx); err != nil {
			return fmt.Errorf("failed to trigger reload: %w", err)
		}
		log.Info("Reload completed successfully")
	} else {
		log.Info("Certificate files unchanged, no reload needed")
	}

	log.Info("Certificate update process completed successfully")
	return nil
}
