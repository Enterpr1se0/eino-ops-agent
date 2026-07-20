package service

import (
	"context"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
)

func TestRemoteConfigTransactionBindsVersionBackupAndValidator(t *testing.T) {
	svc, transport, host := newTestService(t)
	svc.validators["nginx"] = config.Validator{ID: "nginx", Scope: "remote", Program: "nginx", Args: []string{"-t", "-c", "{{path}}"}, TimeoutSeconds: 15, PathPatterns: []string{"/etc/nginx/**"}}
	expected := strings.Repeat("a", 64)
	pending, err := svc.ApplyRemoteConfig(context.Background(), host.ID, "/etc/nginx/nginx.conf", "events {}", "", expected, "nginx", false, "update nginx", "restore backup", "test")
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

func TestVersionedRemoteConfigRequiresObservedSHA(t *testing.T) {
	svc, transport, host := newTestService(t)
	result, err := svc.ApplyRemoteConfigVersioned(context.Background(), host.ID, "/etc/app.conf", "enabled=true\n", "", "", "", false, "enable app", "restore backup", "test")
	if err == nil || !strings.Contains(err.Error(), "expected_sha256 is required") {
		t.Fatalf("missing version was accepted: result=%#v err=%v", result, err)
	}
	if len(transport.calls) != 0 {
		t.Fatal("versionless transaction reached SSH transport")
	}
}

func TestConfigHeredocMarkerCannotTerminateFromContent(t *testing.T) {
	content := "first line\n__OPS_CONFIG_known__\nlast line\n"
	script := buildConfigTransactionScript("/etc/app.conf", "/etc/.app.tmp", "/etc/.app.bak", content, "", strings.Repeat("a", 64), "", "", false)
	if strings.Contains(script, "<<'__OPS_CONFIG_known__'") {
		t.Fatal("transaction reused a delimiter controlled by file content")
	}
	if !strings.Contains(script, content) {
		t.Fatal("transaction lost replacement content")
	}
}

func TestRemoteConfigRejectsSecretsAndRedactionPlaceholders(t *testing.T) {
	svc, transport, host := newTestService(t)
	for _, content := range []string{"password=super-secret", "token=[REDACTED]"} {
		if _, err := svc.ApplyRemoteConfig(context.Background(), host.ID, "/etc/app.conf", content, "", "", "", false, "change", "restore", "test"); err == nil {
			t.Fatalf("sensitive content %q was accepted", content)
		}
	}
	if len(transport.calls) != 0 {
		t.Fatal("rejected sensitive input reached SSH transport")
	}
}
