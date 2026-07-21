package service

import (
	"context"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
)

func TestRemoteFileEditBindsVersionBackupAndValidator(t *testing.T) {
	svc, transport, host := newTestService(t)
	svc.validators["nginx"] = config.Validator{ID: "nginx", Scope: "remote", Program: "nginx", Args: []string{"-t", "-c", "{{path}}"}, TimeoutSeconds: 15, PathPatterns: []string{"/etc/nginx/**"}}
	expected := strings.Repeat("a", 64)
	pending, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/nginx/nginx.conf", "events {}", "", expected, "nginx", false, "update nginx", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" || len(transport.calls) != 0 {
		t.Fatalf("transaction did not wait for approval: %#v", pending)
	}
	if _, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator"); err != nil {
		t.Fatal(err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("transaction executed %d remote calls", len(transport.calls))
	}
	script := transport.calls[0].Script
	for _, required := range []string{"sha256sum -c", ".opspilot-nginx.conf-", "nginx", "cmp -s", "sync -f", "mv -f", "chmod 0600", fileAfterMarker} {
		if !strings.Contains(script, required) {
			t.Fatalf("transaction script missing %q:\n%s", required, script)
		}
	}
}

func TestRemoteFileEditRequiresObservedSHA(t *testing.T) {
	svc, transport, host := newTestService(t)
	result, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/app.conf", "enabled=true\n", "", "", "", false, "enable app", "restore backup", "test")
	if err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("missing version was accepted: result=%#v err=%v", result, err)
	}
	if len(transport.calls) != 0 {
		t.Fatal("versionless transaction reached SSH transport")
	}
}

func TestFileEditHeredocMarkerCannotTerminateFromContent(t *testing.T) {
	content := "first line\n__OPS_FILE_EDIT_known__\nlast line\n"
	script := buildFileEditTransactionScript("/etc/app.conf", "/etc/.app.tmp", "/etc/.app.bak", content, "", strings.Repeat("a", 64), "", "", false)
	if strings.Contains(script, "<<'__OPS_FILE_EDIT_known__'") {
		t.Fatal("transaction reused a delimiter controlled by file content")
	}
	if !strings.Contains(script, content) {
		t.Fatal("transaction lost replacement content")
	}
}

func TestRemoteFileEditRejectsSecretsAndRedactionPlaceholders(t *testing.T) {
	svc, transport, host := newTestService(t)
	for _, content := range []string{"password=super-secret", "token=[REDACTED]"} {
		if _, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/app.conf", content, "", strings.Repeat("a", 64), "", false, "change", "restore", "test"); err == nil {
			t.Fatalf("sensitive content %q was accepted", content)
		}
	}
	if len(transport.calls) != 0 {
		t.Fatal("rejected sensitive input reached SSH transport")
	}
}

func TestRemoteFileEditRequiresExactlyOneChange(t *testing.T) {
	svc, transport, host := newTestService(t)
	expected := strings.Repeat("a", 64)
	for _, change := range []struct {
		content string
		patch   string
	}{
		{},
		{content: "enabled=true\n", patch: "@@ -1 +1 @@\n-false\n+true\n"},
	} {
		if _, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/app.conf", change.content, change.patch, expected, "", false, "change", "restore", "test"); err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("invalid edit was accepted: content=%q patch=%q err=%v", change.content, change.patch, err)
		}
	}
	if _, err := svc.EditRemoteFile(context.Background(), host.ID, "/etc/app.conf", "", "@@ -0,0 +1 @@\n+new\n", "absent", "", false, "create", "remove", "test"); err == nil || !strings.Contains(err.Error(), "cannot create") {
		t.Fatalf("patch creation was accepted: %v", err)
	}
	if len(transport.calls) != 0 {
		t.Fatal("invalid edits reached SSH transport")
	}
}
