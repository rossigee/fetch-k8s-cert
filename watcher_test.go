package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// watchStep is a single event to stream on the watch endpoint. mutate, if
// non-nil, is invoked first to advance the mock's served secret state to match
// the event (as a real apiserver's store would be).
type watchStep struct {
	line   string
	mutate func()
}

// watchMockServer serves a GET for the secret and an optional watch stream.
// GET responses always reflect the current (possibly mutated) state.
type watchMockServer struct {
	server        *httptest.Server
	watchRequests *atomic.Int64
	current       string
}

func (m *watchMockServer) Close() {
	m.server.Close()
}

func (m *watchMockServer) setCurrent(body string) {
	m.current = body
}

func newWatchMockServer(t *testing.T, initialBody string, steps []watchStep, keepOpen bool) *watchMockServer {
	t.Helper()
	m := &watchMockServer{
		watchRequests: &atomic.Int64{},
		current:       initialBody,
	}

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			m.watchRequests.Add(1)
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("response writer does not support flushing")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			for _, step := range steps {
				if step.mutate != nil {
					step.mutate()
				}
				if _, err := fmt.Fprintln(w, step.line); err != nil {
					return
				}
				flusher.Flush()
			}
			if !keepOpen {
				return // close the stream; watcher should reconnect
			}
			// Keep the stream open until the client disconnects.
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, m.current)
	}))
	return m
}

func secretBody(tlsData string) string {
	ca := base64.StdEncoding.EncodeToString([]byte("test-ca-bytes\n"))
	cert := base64.StdEncoding.EncodeToString([]byte(tlsData))
	key := base64.StdEncoding.EncodeToString([]byte("test-key-bytes\n"))
	return fmt.Sprintf(`{"metadata":{"name":"test-secret-name","resourceVersion":"100"},"data":{"ca.crt":"%s","tls.crt":"%s","tls.key":"%s"}}`, ca, cert, key)
}

func watchEventJSON(t string, tlsData string, rv string) string {
	ca := base64.StdEncoding.EncodeToString([]byte("test-ca-bytes\n"))
	cert := base64.StdEncoding.EncodeToString([]byte(tlsData))
	key := base64.StdEncoding.EncodeToString([]byte("test-key-bytes\n"))
	object := fmt.Sprintf(`{"metadata":{"name":"test-secret-name","resourceVersion":"%s"},"data":{"ca.crt":"%s","tls.crt":"%s","tls.key":"%s"}}`, rv, ca, cert, key)
	return fmt.Sprintf(`{"type":"%s","object":%s}`, t, object)
}

func newWatcherTestSetup(t *testing.T, initialBody string, steps []watchStep, keepOpen bool) (*watchMockServer, Config, *SecretWatcher) {
	t.Helper()
	tempDir := t.TempDir()

	mock := newWatchMockServer(t, initialBody, steps, keepOpen)

	config := Config{
		K8SAPIURL:     mock.server.URL,
		Token:         base64.StdEncoding.EncodeToString([]byte("test-token")),
		Namespace:     testNamespace,
		SecretName:    "test-secret-name",
		LocalCAFile:   filepath.Join(tempDir, "ca.pem"),
		LocalCertFile: filepath.Join(tempDir, "cert.pem"),
		LocalKeyFile:  filepath.Join(tempDir, "key.pem"),
		ReloadCommand: fmt.Sprintf("echo reload >> %s", filepath.Join(tempDir, "reload.log")),
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	k8sClient, err := NewK8sClient(config, logger, nil)
	if err != nil {
		t.Fatalf("failed to create k8s client: %v", err)
	}
	// Avoid the transport keep-alive race on intentionally-closed mock watch
	// streams: always open a fresh connection when reconnecting.
	k8sClient.watchClient.Transport = &http.Transport{DisableKeepAlives: true}
	fileManager := NewFileManager(config, logger, nil)
	watcher := NewSecretWatcher(config, k8sClient, fileManager, logger, nil)
	return mock, config, watcher
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(data)
}

func waitForFileContent(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && string(data) == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file %s was never created: %v", path, err)
	}
	t.Fatalf("file %s did not reach expected content; got %q", path, string(data))
}

func TestSecretWatcher_ReactsToChanges(t *testing.T) {
	const initial = "cert-data-v1"
	const updated = "cert-data-v2"

	var mock *watchMockServer
	var config Config
	var watcher *SecretWatcher
	mock, config, watcher = newWatcherTestSetup(t,
		secretBody(initial),
		[]watchStep{{
			mutate: func() { mock.setCurrent(secretBody(updated)) },
			line:   watchEventJSON("MODIFIED", updated, "101"),
		}},
		false)
	defer mock.Close()

	watcher.SetResyncPeriod(0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watcher.Watch(ctx)
		close(done)
	}()

	// The watcher should converge to the mutated secret state (delivered both
	// through the watch event and the reconnect re-sync).
	waitForFileContent(t, config.LocalCertFile, updated)

	cancel()
	<-done

	// A change was observed, so a reload must have been triggered at least once.
	reloadLog := filepath.Join(filepath.Dir(config.LocalCertFile), "reload.log")
	if _, err := os.Stat(reloadLog); err != nil {
		t.Errorf("expected reload to have been triggered after certificate change")
	}
}

func TestSecretWatcher_NoReloadWhenUnchanged(t *testing.T) {
	const data = "cert-data-same"
	mock, config, watcher := newWatcherTestSetup(t,
		secretBody(data),
		[]watchStep{{line: watchEventJSON("MODIFIED", data, "101")}},
		false)
	defer mock.Close()

	// Pre-seed the local files with identical content so neither the initial
	// sync nor the unchanged watch event triggers a reload.
	for path, content := range map[string]string{
		config.LocalCAFile:   "test-ca-bytes\n",
		config.LocalCertFile: data,
		config.LocalKeyFile:  "test-key-bytes\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0640); err != nil {
			t.Fatalf("failed to pre-seed %s: %v", path, err)
		}
	}

	watcher.SetResyncPeriod(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watcher.Watch(ctx)
		close(done)
	}()

	// Wait long enough for the initial sync and the (unchanged) watch event.
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	reloadLog := filepath.Join(filepath.Dir(config.LocalCertFile), "reload.log")
	if _, err := os.Stat(reloadLog); err == nil {
		t.Errorf("reload was triggered despite unchanged certificate: %q", readTestFile(t, reloadLog))
	}
}

func TestSecretWatcher_ReconnectsOnStreamClose(t *testing.T) {
	const data = "cert-data-reconnect"
	mock, _, watcher := newWatcherTestSetup(t, secretBody(data), nil, false)
	defer mock.Close()

	watcher.SetResyncPeriod(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watcher.Watch(ctx)
		close(done)
	}()

	// The watch stream closes immediately, so the watcher must reconnect.
	deadline := time.Now().Add(15 * time.Second)
	for mock.watchRequests.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("watcher did not reconnect; watch requests: %d", mock.watchRequests.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	<-done
}

func TestLoadConfigsDir(t *testing.T) {
	tempDir := t.TempDir()
	content := `
k8sAPIURL: https://kubernetes.example.com:6443
namespace: test-namespace
secretName: test-secret
localCAFile: /tmp/ca.pem
localCertFile: /tmp/cert.pem
localKeyFile: /tmp/key.pem
`
	if err := os.WriteFile(filepath.Join(tempDir, "b.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "a.yaml"), []byte(content), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	configs, err := loadConfigs("", tempDir)
	if err != nil {
		t.Fatalf("loadConfigs failed: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 configs, got %d", len(configs))
	}
	if configs[0].SecretName != "test-secret" {
		t.Errorf("expected deterministic order, got %+v", configs[0])
	}

	if _, err := loadConfigs("", filepath.Join(tempDir, "empty")); err == nil {
		t.Errorf("expected error for empty config dir")
	}
}
