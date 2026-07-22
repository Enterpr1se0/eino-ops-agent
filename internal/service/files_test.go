package service

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
)

func TestRemoteFileEditApprovesDeclarativeDiffAndBuildsScriptAfterApproval(t *testing.T) {
	svc, transport, host := newTestService(t)
	svc.validators["nginx"] = config.Validator{ID: "nginx", Scope: "remote", Program: "nginx", Args: []string{"-t", "-c", "{{path}}"}, TimeoutSeconds: 15, PathPatterns: []string{"/etc/nginx/**"}}
	transport.stdout = []byte(fileValidationMarker + "\n" + fileAfterMarker + "\n" + strings.Repeat("a", 64) + "  /etc/nginx/nginx.conf\n")
	diff := "@@ -1 +1 @@\n-events {}\n+events { worker_connections 1024; }\n"
	pending, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/nginx/nginx.conf", diff, "nginx", false, "update nginx", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" || len(transport.calls) != 0 || pending.Change == nil || pending.Change.Additions != 1 || pending.Change.Deletions != 1 {
		t.Fatalf("declarative edit did not wait for approval: %#v", pending)
	}
	run, err := svc.store.GetRun(context.Background(), pending.RunID)
	if err != nil {
		t.Fatal(err)
	}
	var approved domain.ExecRequest
	if err := json.Unmarshal([]byte(run.RequestJSON), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.Mode != domain.ExecRemoteEdit || approved.Script != "" || approved.Change == nil || approved.Change.Diff == "" || approved.ExpectedSHA256 != "" || approved.Rollback != "" {
		t.Fatalf("approval persisted execution internals or removed fields: %#v", approved)
	}
	if _, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator"); err != nil {
		t.Fatal(err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("edit executed %d remote calls", len(transport.calls))
	}
	script := transport.calls[0].Script
	for _, required := range []string{"patch --batch --forward", "nginx", "sync -f", "mv -f", fileAfterMarker, "-events {}", "+events { worker_connections 1024; }"} {
		if !strings.Contains(script, required) {
			t.Fatalf("edit script missing %q:\n%s", required, script)
		}
	}
	for _, removed := range []string{"sha256sum -c", "cmp -s", ".bak", "__OPS_FILE_BEFORE__", "__OPS_FILE_BACKUP__"} {
		if removed != "" && strings.Contains(script, removed) {
			t.Fatalf("removed conflict/backup logic %q remains:\n%s", removed, script)
		}
	}
}

func TestFileEditHeredocMarkerCannotTerminateFromDiff(t *testing.T) {
	change, err := buildEditChange("/etc/app.conf", "@@ -1 +1 @@\n-old\n+__OPS_FILE_EDIT_known__\n")
	if err != nil {
		t.Fatal(err)
	}
	script := buildRemoteFileChangeScript("/etc/app.conf", "/etc/.app.tmp", change, "")
	if strings.Contains(script, "<<'__OPS_FILE_EDIT_known__'") {
		t.Fatal("edit reused a delimiter controlled by diff content")
	}
	if !strings.Contains(script, change.Diff) {
		t.Fatal("edit lost the normalized diff")
	}
}

func TestRemoteFileEditRejectsSecretsAndMalformedDiffs(t *testing.T) {
	svc, transport, host := newTestService(t)
	for _, diff := range []string{
		"@@ -1 +1 @@\n-password=old\n+password=super-secret\n",
		"@@ -1 +1 @@\n-token=old\n+token=[REDACTED]\n",
		"not a unified diff",
		"@@ -1,2 +1 @@\n-old\n+new\n",
	} {
		if _, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/app.conf", diff, "", false, "change", "test"); err == nil {
			t.Fatalf("invalid diff was accepted: %q", diff)
		}
	}
	if len(transport.calls) != 0 {
		t.Fatal("rejected input reached SSH transport")
	}
}

func TestBuildEditChangeNormalizesHeadersAndCountsLines(t *testing.T) {
	change, err := buildEditChange("app.conf", "--- old\n+++ new\n@@ -1,2 +1,3 @@\n a\n-b\n+c\n+d\n")
	if err != nil {
		t.Fatal(err)
	}
	if change.Additions != 2 || change.Deletions != 1 || !strings.HasPrefix(change.Diff, "--- app.conf\n+++ app.conf\n") {
		t.Fatalf("unexpected normalized change: %#v", change)
	}
}

func TestRemoteFileChangeScriptsApplyWithoutPersistentBackups(t *testing.T) {
	if _, err := exec.LookPath("patch"); err != nil {
		t.Skip("patch is unavailable")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "app.conf")
	if err := os.WriteFile(target, []byte("enabled=false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	change, err := buildEditChange(target, "@@ -1 +1 @@\n-enabled=false\n+enabled=true\n")
	if err != nil {
		t.Fatal(err)
	}
	script := buildRemoteFileChangeScript(target, filepath.Join(directory, ".edit.tmp"), change, "")
	command := exec.Command("bash", "-se")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("edit script failed: %v\n%s\n%s", err, output, script)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "enabled=true\n" {
		t.Fatalf("edited content=%q err=%v", content, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bak") || strings.HasSuffix(entry.Name(), ".orig") || strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("file change left a backup or temporary file: %s", entry.Name())
		}
	}
}
