package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"eino-ops-agent/internal/config"
)

func TestPrepareQuickStartUsesApplicationDirectoryAndKeepsConfig(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	appDir := t.TempDir()

	path, created, err := prepareQuickStartIn(appDir)
	if err != nil {
		t.Fatal(err)
	}
	if !created || path != filepath.Join(appDir, config.DefaultFileName) {
		t.Fatalf("path=%q created=%v", path, created)
	}
	current, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if current != appDir {
		t.Fatalf("working directory = %q, want %q", current, appDir)
	}

	path, created, err = prepareQuickStartIn(appDir)
	if err != nil {
		t.Fatal(err)
	}
	if created || path != filepath.Join(appDir, config.DefaultFileName) {
		t.Fatalf("second start path=%q created=%v", path, created)
	}
}

func TestLocalWebURLUsesLoopbackForWildcardListener(t *testing.T) {
	address := &net.TCPAddr{IP: net.IPv6zero, Port: 49152}
	if got := localWebURL(address); got != "http://127.0.0.1:49152" {
		t.Fatalf("local URL = %q", got)
	}
}
