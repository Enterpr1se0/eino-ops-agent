package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/policy"
	"eino-ops-agent/internal/security"
	"eino-ops-agent/internal/store"
)

func newWorkspaceService(t *testing.T, access string) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	dataDir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dataDir, "workspace.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	encryptor, err := security.NewEncryptor("", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := policy.Load("")
	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.Workspaces = []config.Workspace{{ID: "project", Root: root, Access: access}}
	return New(st, engine, nil, encryptor, security.NewRedactor(), cfg.Limits, cfg), root
}

func TestWorkspaceReadPatchAndTraversalProtection(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	path := filepath.Join(root, "app.conf")
	if err := os.WriteFile(path, []byte("port=8080\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	read, err := svc.ReadWorkspaceFile(context.Background(), "project", "app.conf", 1024, 0, "test")
	if err != nil {
		t.Fatal(err)
	}
	if read.Status != "completed" || read.Stdout != "port=8080\n" || read.File == nil || read.File.SHA256 == "" {
		t.Fatalf("unexpected workspace read: %#v", read)
	}
	patch := "--- app.conf\n+++ app.conf\n@@ -1,1 +1,1 @@\n-port=8080\n+port=9090\n"
	pending, err := svc.ApplyWorkspacePatch(context.Background(), "project", "app.conf", patch, read.File.SHA256, "", "change port", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" {
		t.Fatalf("workspace write skipped approval: %#v", pending)
	}
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "", "reviewed", "operator")
	if err != nil || approved.Status != "completed" {
		t.Fatalf("workspace patch failed: %#v err=%v", approved, err)
	}
	content, _ := os.ReadFile(path)
	if string(content) != "port=9090\n" {
		t.Fatalf("patch result = %q", content)
	}
	if _, err := svc.ReadWorkspaceFile(context.Background(), "project", "../outside", 100, 0, "test"); err == nil || !strings.Contains(err.Error(), "relative") {
		t.Fatalf("workspace traversal was not rejected: %v", err)
	}
}

func TestWorkspacePatchDetectsVersionConflict(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	path := filepath.Join(root, "app.conf")
	_ = os.WriteFile(path, []byte("a\n"), 0o600)
	stale := fmt.Sprintf("%x", sha256.Sum256([]byte("old\n")))
	patch := "--- app.conf\n+++ app.conf\n@@ -1 +1 @@\n-a\n+b\n"
	pending, err := svc.ApplyWorkspacePatch(context.Background(), "project", "app.conf", patch, stale, "", "change", "restore", "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Approve(context.Background(), pending.ApprovalID, "", "reviewed", "operator")
	if err == nil || result.ExitCode != 73 {
		t.Fatalf("expected conflict, got %#v err=%v", result, err)
	}
}

func TestApplyUnifiedPatchRejectsMismatchedContext(t *testing.T) {
	if _, err := applyUnifiedPatch("a\n", "@@ -1 +1 @@\n-wrong\n+b\n"); err == nil {
		t.Fatal("mismatched patch context was accepted")
	}
	if _, err := applyUnifiedPatch("a\n", "@@ -1,2 +1,1 @@\n-a\n+b\n"); err == nil || !strings.Contains(err.Error(), "line counts") {
		t.Fatalf("mismatched hunk counts were accepted: %v", err)
	}
	updated, err := applyUnifiedPatch("", "@@ -0,0 +1,1 @@\n+first\n")
	if err != nil || updated != "first" {
		t.Fatalf("empty file insertion failed: updated=%q err=%v", updated, err)
	}
}

func TestWorkspaceListHidesSensitiveControlPlaneNames(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_only")
	for _, name := range []string{"README.md", ".env", "deploy-credentials.json", "master.key"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := svc.ListWorkspaceFiles(context.Background(), "project", ".", "test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Stdout, "README.md") || strings.Contains(result.Stdout, ".env") || strings.Contains(result.Stdout, "credentials") || strings.Contains(result.Stdout, "master.key") {
		t.Fatalf("workspace listing exposed sensitive names: %s", result.Stdout)
	}
}

func TestWorkspacePostValidationFailureRestoresOriginalAtomically(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	path := filepath.Join(root, "app.conf")
	if err := os.WriteFile(path, []byte("port=8080\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	validator := filepath.Join(t.TempDir(), "validate-fixture")
	validatorBody := "#!/bin/sh\ncase \"$1\" in *.tmp) exit 0;; *) exit 1;; esac\n"
	if err := os.WriteFile(validator, []byte(validatorBody), 0o700); err != nil {
		t.Fatal(err)
	}
	svc.validators["fixture"] = config.Validator{ID: "fixture", Scope: "workspace", Program: validator, Args: []string{"{{path}}"}, TimeoutSeconds: 5, PathPatterns: []string{filepath.Join(root, "**")}}
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte("port=8080\n")))
	patch := "@@ -1 +1 @@\n-port=8080\n+port=9090\n"
	pending, err := svc.ApplyWorkspacePatch(context.Background(), "project", "app.conf", patch, expected, "fixture", "change port", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Approve(context.Background(), pending.ApprovalID, "", "reviewed", "operator")
	if err == nil || result.ExitCode != 74 {
		t.Fatalf("expected post-validation rollback, result=%#v err=%v", result, err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "port=8080\n" {
		t.Fatalf("automatic rollback did not restore the original: content=%q err=%v", content, readErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("automatic rollback did not preserve mode: info=%#v err=%v", info, statErr)
	}
}

func TestWorkspaceAdminUploadIsAtomicAndNeverOverwrites(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	content := []byte("package main\n")
	result, err := svc.UploadWorkspaceFile(context.Background(), "project", "main.go", "ignored.txt", bytes.NewReader(content), "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	wantSHA := fmt.Sprintf("%x", sha256.Sum256(content))
	if result.Path != "main.go" || result.Size != int64(len(content)) || result.SHA256 != wantSHA {
		t.Fatalf("unexpected upload result: %#v", result)
	}
	stored, err := os.ReadFile(filepath.Join(root, "main.go"))
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatalf("uploaded content mismatch: %q err=%v", stored, err)
	}
	info, err := os.Stat(filepath.Join(root, "main.go"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("uploaded mode = %v err=%v", info.Mode().Perm(), err)
	}
	if _, err := svc.UploadWorkspaceFile(context.Background(), "project", "main.go", "main.go", bytes.NewBufferString("overwrite\n"), "admin-web"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing file was overwritten: %v", err)
	}
	stored, _ = os.ReadFile(filepath.Join(root, "main.go"))
	if !bytes.Equal(stored, content) {
		t.Fatalf("failed overwrite changed existing content: %q", stored)
	}
	listing, err := svc.ListAdminWorkspaceFiles("project", ".")
	if err != nil || len(listing.Entries) != 1 || listing.Entries[0].Name != "main.go" || listing.Entries[0].Type != "file" {
		t.Fatalf("uploaded file was not visible in the admin listing: %#v err=%v", listing, err)
	}
	for _, path := range []string{"../escape", ".env.production", `nested\windows.txt`} {
		if _, err := svc.UploadWorkspaceFile(context.Background(), "project", path, "file", bytes.NewBufferString("x"), "admin-web"); err == nil {
			t.Fatalf("unsafe upload path %q was accepted", path)
		}
	}
	capabilities := svc.ListAdminWorkspaceCapabilities()
	if len(capabilities) != 1 || capabilities[0].Root != root {
		t.Fatalf("admin capabilities did not include the root: %#v", capabilities)
	}
	preview, err := svc.PreviewAdminWorkspaceFile("project", "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Path != "main.go" || preview.Content != string(content) || preview.SHA256 != wantSHA || preview.Binary || preview.Truncated {
		t.Fatalf("unexpected workspace preview: %#v", preview)
	}
	deleted, err := svc.DeleteAdminWorkspaceFile(context.Background(), "project", "main.go", "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted.Recoverable || deleted.TrashID == "" || deleted.Path != "main.go" || deleted.SHA256 != wantSHA {
		t.Fatalf("unexpected delete result: %#v", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, "main.go")); !os.IsNotExist(err) {
		t.Fatalf("deleted file remains at its original path: %v", err)
	}
	recovered, err := os.ReadFile(filepath.Join(root, ".opspilot-trash", deleted.TrashID))
	if err != nil || !bytes.Equal(recovered, content) {
		t.Fatalf("recovery copy mismatch: content=%q err=%v", recovered, err)
	}
	listing, err = svc.ListAdminWorkspaceFiles("project", ".")
	if err != nil || len(listing.Entries) != 0 {
		t.Fatalf("recovery directory leaked into listing: %#v err=%v", listing, err)
	}
	if _, err := svc.PreviewAdminWorkspaceFile("project", filepath.Join(".opspilot-trash", deleted.TrashID)); err == nil || !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("recovery directory was accessible through Web preview: %v", err)
	}
}

func TestWorkspaceUploadRejectsReadOnlyWorkspace(t *testing.T) {
	svc, _ := newWorkspaceService(t, "read_only")
	if _, err := svc.UploadWorkspaceFile(context.Background(), "project", "file.txt", "file.txt", bytes.NewBufferString("x"), "admin-web"); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("read-only Workspace accepted upload: %v", err)
	}
	if _, err := svc.DeleteAdminWorkspaceFile(context.Background(), "project", "file.txt", "admin-web"); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("read-only Workspace accepted delete: %v", err)
	}
}

func TestWorkspaceDirectUploadUsesOneVersionBoundApproval(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_only")
	transport := &fakeTransport{}
	svc.transport = transport
	host, err := svc.SaveHost(context.Background(), domain.HostInput{
		Name: "destination", Address: "192.0.2.40", Port: 22, User: "ops", AuthType: "agent", SudoMode: "none",
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("version: 1\n")
	localPath := filepath.Join(root, "deploy.yaml")
	if err := os.WriteFile(localPath, content, 0o640); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(content))
	pending, err := svc.UploadWorkspaceFileToHost(context.Background(), host.ID, "project", "deploy.yaml", digest, "/tmp/deploy.yaml", "deploy exact fixture", "remove remote fixture", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" || pending.Risk != domain.RiskChange {
		t.Fatalf("direct Workspace upload bypassed one approval: %#v", pending)
	}
	approval, err := svc.Store().GetApproval(context.Background(), pending.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(approval.RequestJSON, root) || !strings.Contains(approval.RequestJSON, digest) || !strings.Contains(approval.RequestJSON, `"mode":"workspace_upload"`) {
		t.Fatalf("approval did not bind the safe source version without exposing its root: %s", approval.RequestJSON)
	}
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "", "reviewed exact source and destination", "operator")
	if err != nil || approved.Status != "completed" {
		t.Fatalf("approved direct upload failed: result=%#v err=%v", approved, err)
	}
	if len(transport.calls) != 1 || transport.calls[0].Mode != domain.ExecWorkspaceUpload || transport.calls[0].LocalPath != localPath || transport.calls[0].ExpectedSHA256 != digest {
		t.Fatalf("transport did not receive the resolved version-bound source: %#v", transport.calls)
	}

	stale, err := svc.UploadWorkspaceFileToHost(context.Background(), host.ID, "project", "deploy.yaml", digest, "/tmp/deploy-2.yaml", "detect source change", "remove remote fixture", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte("version: 2\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(context.Background(), stale.ApprovalID, "", "reviewed before source changed", "operator"); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("changed Workspace source was uploaded after approval: %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("version-conflicted source reached transport: %#v", transport.calls)
	}
}
