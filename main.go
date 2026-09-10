package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	version = "3.0.0" // Set by build flags
)

func main() {
	// Define command-line flags
	configFilePath := flag.String("f", "", "Path to the configuration file")
	configDirPath := flag.String("d", "", "Path to a directory of configuration files (one per secret)")
	watchFlag := flag.Bool("w", false, "Run in watch mode: fetch once on startup, then watch the secret(s) for changes")
	resync := flag.Duration("resync", defaultResyncPeriod, "How often to re-fetch each secret as a safety net (watch mode only, 0 to disable)")
	verboseFlag := flag.Bool("v", false, "Enable verbose logging (info level)")
	versionFlag := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("fetch-k8s-cert version %s\n", version)
		os.Exit(0)
	}

	if *configFilePath == "" && *configDirPath == "" {
		fmt.Println("Please provide a path to the configuration file using -f, or a directory of configurations using -d.")
		fmt.Printf("Usage: fetch-k8s-cert -f <config-file> [-v]\n")
		fmt.Printf("       fetch-k8s-cert -d <config-dir> [-v]\n")
		fmt.Printf("       fetch-k8s-cert -w -d <config-dir> [--resync 24h] [-v]\n")
		os.Exit(1)
	}
	if *configFilePath != "" && *configDirPath != "" {
		fmt.Println("Please provide either -f or -d, not both.")
		os.Exit(1)
	}

	// Load configuration(s)
	configs, err := loadConfigs(*configFilePath, *configDirPath)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Override log level if verbose flag is set
	if *verboseFlag {
		for i := range configs {
			configs[i].Observability.LogLevel = "info" //nolint:goconst
		}
	}

	// Initialize observability from the first configuration
	obs, err := NewObservabilityManager(configs[0].Observability)
	if err != nil {
		fmt.Printf("Error initializing observability: %v\n", err)
		os.Exit(1)
	}

	// Get logger from observability
	log := obs.Logger()

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

	if !*watchFlag {
		for i := range configs {
			if err := run(ctx, configs[i], log, obs); err != nil {
				log.WithFields(logrus.Fields{
					"namespace": configs[i].Namespace,  //nolint:goconst
					"secret":    configs[i].SecretName, //nolint:goconst
				}).WithError(err).Error("Application failed")
				_ = obs.Shutdown(context.Background())
				os.Exit(1)
			}
		}
		log.Info("Shutting down...")
		if err := obs.Shutdown(ctx); err != nil {
			log.WithError(err).Error("Error during observability shutdown")
		}
		return
	}

	// Watch mode: one watcher per configuration.
	for i := range configs {
		config := configs[i]
		k8sClient, err := NewK8sClient(config, log, obs.Metrics())
		if err != nil {
			log.WithFields(logrus.Fields{
				"namespace": config.Namespace,  //nolint:goconst
				"secret":    config.SecretName, //nolint:goconst
			}).WithError(err).Error("Failed to create Kubernetes client")
			continue
		}
		fileManager := NewFileManager(config, log, obs.Metrics())
		watcher := NewSecretWatcher(config, k8sClient, fileManager, log, obs.Metrics())
		watcher.SetResyncPeriod(*resync)
		go watcher.Watch(ctx)
	}

	log.Info("Watch mode started, waiting for certificate changes")
	<-ctx.Done()
	log.Info("Shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := obs.Shutdown(shutdownCtx); err != nil {
		log.WithError(err).Error("Error during observability shutdown")
	}
}

// loadConfigs loads a single configuration file or all *.yaml files in a
// directory, deterministically ordered by filename.
func loadConfigs(configFilePath, configDirPath string) ([]Config, error) {
	if configFilePath != "" {
		config, err := LoadConfigFromFile(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from file: %w", err)
		}
		return []Config{*config}, nil
	}

	files, err := filepath.Glob(filepath.Join(configDirPath, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to find config files in %s: %w", configDirPath, err)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.yaml config files found in %s", configDirPath)
	}

	configs := make([]Config, 0, len(files))
	for _, f := range files {
		config, err := LoadConfigFromFile(f)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from file %s: %w", f, err)
		}
		configs = append(configs, *config)
	}
	return configs, nil
}

// run executes the main application logic (single fetch)
func run(ctx context.Context, config Config, log *logrus.Logger, obs *ObservabilityManager) error {
	log.WithFields(logrus.Fields{
		"version":             version,
		"namespace":           config.Namespace,  //nolint:goconst
		"secret":              config.SecretName, //nolint:goconst
		"k8s_api":             config.K8SAPIURL,
		"use_intermediate_ca": config.UseIntermediateCA,
	}).Info("Starting fetch-k8s-cert")

	// Create Kubernetes client
	k8sClient, err := NewK8sClient(config, log, obs.Metrics())
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Create file manager
	fileManager := NewFileManager(config, log, obs.Metrics())

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
