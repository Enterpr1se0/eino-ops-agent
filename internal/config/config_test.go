package config

import (
	"os"
	"path/filepath"
	"testing"
)

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
