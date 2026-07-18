package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAddsDefaultWorkspaceRelativeToStartupDirectory(t *testing.T) {
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
	if len(cfg.Workspaces) != 1 {
		t.Fatalf("default workspace count = %d", len(cfg.Workspaces))
	}
	workspace := cfg.Workspaces[0]
	if workspace.ID != "default" || workspace.Access != "read_write" || workspace.Root != filepath.Join(root, "workspace") || !workspace.AutoCreate {
		t.Fatalf("unexpected default workspace: %#v", workspace)
	}
}

func TestLoadCanDisableDefaultWorkspace(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("default_workspace_dir: \"\"\nworkspaces: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Workspaces) != 0 {
		t.Fatalf("disabled default workspace was still configured: %#v", cfg.Workspaces)
	}
}
