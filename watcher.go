package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

// Kubernetes watch event types.
const (
	watchEventAdded    = "ADDED"
	watchEventModified = "MODIFIED"
	watchEventDeleted  = "DELETED"
	watchEventBookmark = "BOOKMARK"
	watchEventError    = "ERROR"
)

// Nominal intervals for the watcher.
const (
	defaultReconnectInterval = time.Second
	maxReconnectInterval     = time.Minute
	defaultResyncPeriod      = 24 * time.Hour
)

// SecretWatcher keeps the local certificate files in sync with a Kubernetes
// TLS secret. It performs a full fetch on startup and then waits on the
// Kubernetes watch API, re-running the fetch pipeline whenever the secret
// changes. Unlike the previous poll-and-sleep pattern, an idle watcher makes
// no periodic Kubernetes requests:
//
//   - updates are delivered by the watch stream (event-driven),
//   - a periodic re-sync (default 24h, overridable) acts as a safe convergence
//     net,
//   - on stream close/error the watcher reconnects with exponential backoff and
//     re-syncs as part of reconnection.
type SecretWatcher struct {
	config            Config
	k8s               *K8sClient
	fileMgr           *FileManager
	logger            *logrus.Logger
	metrics           *Metrics
	reconnectInterval time.Duration
	resync            time.Duration
}

// NewSecretWatcher creates a secret watcher for the given configuration.
func NewSecretWatcher(config Config, k *K8sClient, fm *FileManager, logger *logrus.Logger, metrics *Metrics) *SecretWatcher {
	return &SecretWatcher{
		config:            config,
		k8s:               k,
		fileMgr:           fm,
		logger:            logger,
		metrics:           metrics,
		reconnectInterval: defaultReconnectInterval,
		resync:            defaultResyncPeriod,
	}
}

// SetResyncPeriod overrides the periodic safety-net re-sync interval. A value
// of zero disables periodic re-syncing.
func (w *SecretWatcher) SetResyncPeriod(period time.Duration) {
	w.resync = period
}

// Watch runs the watcher until ctx is cancelled. Failures are logged and never
// kill the watcher; transient errors are handled with reconnect backoff.
func (w *SecretWatcher) Watch(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		if resourceVersion, err := w.sync(ctx); err != nil {
			w.log(ctx).WithError(err).Error("Sync failed, will retry")
			if !w.wait(ctx) {
				return
			}
			continue
		} else {
			w.reconnectInterval = defaultReconnectInterval

			err := w.watchStream(ctx, resourceVersion)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				w.log(ctx).WithError(err).Warn("Watch stream failed, reconnecting")
			} else {
				w.log(ctx).Info("Watch stream closed, reconnecting")
			}
		}
		if !w.wait(ctx) {
			return
		}
	}
}

// sync fetches the current secret and updates the local files, reloading the
// consuming service only if something actually changed. On success it returns
// the resourceVersion of the secret that was observed.
func (w *SecretWatcher) sync(ctx context.Context) (string, error) {
	tlsBundle, resourceVersion, err := w.k8s.GetTLSBundleWithRV(ctx)
	if err != nil {
		return "", err
	}

	changed, err := w.fileMgr.UpdateCertificateFiles(ctx, tlsBundle)
	if err != nil {
		return resourceVersion, err
	}

	if changed {
		w.log(ctx).Info("Certificate files changed, triggering reload")
		if err := w.fileMgr.TriggerReload(ctx); err != nil {
			return resourceVersion, err
		}
		w.log(ctx).Info("Reload completed successfully")
	} else {
		w.log(ctx).Info("Certificate files unchanged, no reload needed")
	}

	return resourceVersion, nil
}

// watchStream streams watch events and re-syncs on every change until the
// stream closes or ctx is cancelled. Re-syncs use the bytes-equal file compare
// in FileManager, so an unchanged certificate never triggers a reload.
func (w *SecretWatcher) watchStream(ctx context.Context, resourceVersion string) error {
	log := w.log(ctx)

	body, err := w.k8s.WatchSecret(ctx, resourceVersion)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	var resyncTicker *time.Ticker
	var resyncCh <-chan time.Time
	if w.resync > 0 {
		resyncTicker = time.NewTicker(w.resync)
		resyncCh = resyncTicker.C
		defer resyncTicker.Stop()
	}

	decoder := json.NewDecoder(body)

	for {
		var event watchEvent
		err := decoder.Decode(&event)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil // stream closed cleanly; outer loop reconnects + re-syncs
			}
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-resyncCh:
			log.Info("Resync interval reached, re-syncing")
			if _, err := w.sync(ctx); err != nil {
				log.WithError(err).Error("Resync failed")
			}
		default:
		}

		switch event.Type {
		case watchEventAdded, watchEventModified, watchEventDeleted:
			log.WithField("type", event.Type).Info("Certificate secret changed, re-syncing")
			if _, err := w.sync(ctx); err != nil {
				log.WithError(err).Error("Sync after watch event failed")
			}
		case watchEventBookmark:
			// Progression marker; nothing to do, we are already fully reactive.
			log.Debug("Received watch bookmark")
		case watchEventError:
			return fmt.Errorf("kubernetes watch error event received")
		default:
			log.WithField("type", event.Type).Debug("Ignoring unknown watch event type")
		}
	}
}

// watchEvent is a single entry in a Kubernetes watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// wait backs off with exponential delay, returning false if ctx is done.
func (w *SecretWatcher) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(w.reconnectInterval):
		if w.reconnectInterval*2 <= maxReconnectInterval {
			w.reconnectInterval *= 2
		}
		return true
	}
}

// log returns a per-secret logrus entry.
func (w *SecretWatcher) log(_ context.Context) *logrus.Entry {
	return w.logger.WithFields(logrus.Fields{
		"namespace": w.config.Namespace,  //nolint:goconst
		"secret":    w.config.SecretName, //nolint:goconst
	})
}
