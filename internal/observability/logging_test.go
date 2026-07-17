package observability

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
