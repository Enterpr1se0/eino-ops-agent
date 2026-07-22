package observability

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBufferFiltersAndRedactsSensitiveFields(t *testing.T) {
	buffer := &Buffer{limit: 10}
	level := slog.LevelDebug
	logger := slog.New(&bufferHandler{buffer: buffer, level: level}).With("component", "ssh")
	logger.InfoContext(context.Background(), "execution completed",
		"run_id", "run_test", "password", "do-not-expose", "stdout_bytes", 128)

	entries := buffer.recent(LogFilter{Level: "info", Component: "ssh", Query: "run_test", Limit: 5})
	if len(entries) != 1 {
		t.Fatalf("expected one matching entry, got %#v", entries)
	}
	if entries[0].Fields["password"] != "[REDACTED]" {
		t.Fatalf("sensitive field was not redacted: %#v", entries[0].Fields)
	}
	if entries[0].Fields["stdout_bytes"] != int64(128) {
		t.Fatalf("safe output metric was unexpectedly hidden: %#v", entries[0].Fields)
	}
	if got := buffer.recent(LogFilter{Level: "error", Limit: 5}); len(got) != 0 {
		t.Fatalf("minimum level filter returned info entry: %#v", got)
	}
}

func TestRotatingWriterKeepsBoundedBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ops-agent.log")
	writer, err := newRotatingWriter(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.file.Close()
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "second\n" || string(backup) != "first\n" {
		t.Fatalf("unexpected rotation current=%q backup=%q", current, backup)
	}
}

func TestWriteArchiveIncludesCurrentLogAndRotatedBackups(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "ops-agent.log")
	files := map[string]string{
		"ops-agent.log":   "current\n",
		"ops-agent.log.1": "backup-one\n",
		"ops-agent.log.2": "backup-two\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	previousFile := activeFile.Load()
	activeFile.Store(&path)
	t.Cleanup(func() {
		activeFile.Store(previousFile)
	})

	var output bytes.Buffer
	if err := WriteArchive(&output); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != len(files) {
		t.Fatalf("archive entries = %d, want %d", len(reader.File), len(files))
	}
	for _, archived := range reader.File {
		entry, err := archived.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(entry)
		entry.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != files[archived.Name] {
			t.Fatalf("archive %q = %q, want %q", archived.Name, content, files[archived.Name])
		}
	}
}

func TestWriteArchiveFallsBackToInMemoryJSONL(t *testing.T) {
	disabled := "-"
	buffer := &Buffer{limit: 10, entries: []LogEntry{{Level: "debug", Message: "memory event", Component: "test"}}}
	previousFile := activeFile.Load()
	previousBuffer := activeBuffer.Load()
	activeFile.Store(&disabled)
	activeBuffer.Store(buffer)
	t.Cleanup(func() {
		activeFile.Store(previousFile)
		activeBuffer.Store(previousBuffer)
	})

	var output bytes.Buffer
	if err := WriteArchive(&output); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != 1 || reader.File[0].Name != "ops-agent-memory.jsonl" {
		t.Fatalf("unexpected archive entries: %#v", reader.File)
	}
	entry, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(entry)
	entry.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"message":"memory event"`) {
		t.Fatalf("in-memory log was not exported: %s", content)
	}
}

func TestEmptyLogLevelDefaultsToDebug(t *testing.T) {
	level, err := parseLevel("")
	if err != nil {
		t.Fatal(err)
	}
	if level != slog.LevelDebug {
		t.Fatalf("empty level = %s, want debug", level)
	}
}
