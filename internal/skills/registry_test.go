package skills

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryInitializesBuiltinsAndKeepsPermanentDeletion(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	registry := NewRegistry(root)
	items, err := registry.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("initialized skills=%d, want 3", len(items))
	}
	if err := registry.Delete("linux-diagnosis"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Get("linux-diagnosis"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted skill error=%v", err)
	}

	restarted := NewRegistry(root)
	items, err = restarted.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("permanently deleted skill reappeared: %#v", items)
	}
}

func TestRegistrySavesAndImportsManagedSkills(t *testing.T) {
	registry := NewRegistry(filepath.Join(t.TempDir(), "skills"))
	saved, err := registry.Save("redis-recovery", "# Redis Recovery\n\nInspect persistence and bounded logs first.")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Name != "redis-recovery" || saved.Content == "" || saved.ContentSHA256 == "" || saved.FileCount != 1 {
		t.Fatalf("unexpected saved skill: %#v", saved)
	}

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	mainFile, _ := writer.Create("kubernetes-debug/SKILL.md")
	_, _ = mainFile.Write([]byte("# Kubernetes Debug\n\nInspect events before changing workloads."))
	reference, _ := writer.Create("kubernetes-debug/references/events.md")
	_, _ = reference.Write([]byte("Use bounded event windows."))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	imported, err := registry.Import("kubernetes-debug", "kubernetes-debug.zip", bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if imported.FileCount != 2 || imported.Content == "" {
		t.Fatalf("unexpected imported skill: %#v", imported)
	}
	if _, err := os.Stat(filepath.Join(registry.Root(), "kubernetes-debug", "references", "events.md")); err != nil {
		t.Fatal(err)
	}
	replaced, err := registry.Import("kubernetes-debug", "replacement.md", bytes.NewBufferString("# Replacement\n\nUse the replacement workflow."))
	if err != nil {
		t.Fatal(err)
	}
	if replaced.FileCount != 1 {
		t.Fatalf("Markdown upload did not replace the prior package: %#v", replaced)
	}
	if _, err := os.Stat(filepath.Join(registry.Root(), "kubernetes-debug", "references", "events.md")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old package reference survived replacement: %v", err)
	}
}

func TestRegistryRejectsZIPPathTraversal(t *testing.T) {
	registry := NewRegistry(filepath.Join(t.TempDir(), "skills"))
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	mainFile, _ := writer.Create("SKILL.md")
	_, _ = mainFile.Write([]byte("# Valid main"))
	escape, _ := writer.Create("../escaped.txt")
	_, _ = escape.Write([]byte("escape"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Import("invalid", "invalid.zip", bytes.NewReader(archive.Bytes())); err == nil {
		t.Fatal("path-traversing ZIP was accepted")
	}
}

func TestRegistryEnabledStatePersists(t *testing.T) {
	root := filepath.Join(t.TempDir(), "skills")
	registry := NewRegistry(root)
	disabled, err := registry.SetEnabled("linux-diagnosis", false)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled {
		t.Fatalf("disabled skill is enabled: %#v", disabled)
	}

	restarted := NewRegistry(root)
	loaded, err := restarted.Get("linux-diagnosis")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Enabled {
		t.Fatalf("disabled state did not persist: %#v", loaded)
	}
	enabled, err := restarted.SetEnabled("linux-diagnosis", true)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || enabled.FileCount != 1 {
		t.Fatalf("unexpected enabled skill metadata: %#v", enabled)
	}
}
