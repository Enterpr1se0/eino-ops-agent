package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEnsureDefaultFileCreatesLoadableConfigWithoutOverwriting(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, DefaultFileName)
	created, err := EnsureDefaultFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("default configuration was not created")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "listen_address: 0.0.0.0:8080") || strings.Contains(string(data), "password:") {
		t.Fatalf("unexpected generated configuration:\n%s", data)
	}
	var loaded Config
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("parse generated configuration: %v", err)
	}
	if loaded.ListenAddress != Default().ListenAddress || loaded.DatabasePath != Default().DatabasePath {
		t.Fatalf("generated defaults were not preserved: %#v", loaded)
	}

	const replacement = "listen_address: 127.0.0.1:9090\n"
	if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err = EnsureDefaultFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("existing configuration was reported as created")
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != replacement {
		t.Fatalf("existing configuration was overwritten: %q", data)
	}
}

func TestLoadResolvesWorkspaceDirectoryRelativeToStartupDirectory(t *testing.T) {
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	cfg, err := Load(filepath.Join(root, "missing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WorkspaceDir != filepath.Join(root, "workspace") {
		t.Fatalf("workspace directory = %q", cfg.WorkspaceDir)
	}
	if cfg.WorkspaceSandboxPath != "bwrap" {
		t.Fatalf("default workspace sandbox = %q", cfg.WorkspaceSandboxPath)
	}
}

func TestLoadRejectsWorkspaceDirectoryOverlappingDataDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: runtime\nworkspace_dir: runtime/workspaces\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	if _, err := Load(path); err == nil {
		t.Fatal("overlapping workspace directory was accepted")
	}
}
