package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
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
	workspaceRoot := t.TempDir()
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
	svc := New(st, engine, nil, encryptor, security.NewRedactor(), cfg.Limits, cfg)
	if err := svc.InitializeWorkspaces(ctx, workspaceRoot); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteAdminWorkspace(ctx, "default", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAdminWorkspace(ctx, domain.WorkspaceInput{ID: "project", Access: access}, "test"); err != nil {
		t.Fatal(err)
	}
	return svc, filepath.Join(workspaceRoot, "project")
}

func TestWorkspaceAdminCreateUpdateAndRemove(t *testing.T) {
	svc, projectRoot := newWorkspaceService(t, "read_write")
	created, err := svc.CreateAdminWorkspace(context.Background(), domain.WorkspaceInput{ID: "docs", Access: "read_only"}, "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "docs" || created.Access != "read_only" {
		t.Fatalf("unexpected created workspace: %#v", created)
	}
	docsRoot := filepath.Join(filepath.Dir(projectRoot), "docs")
	if info, err := os.Stat(docsRoot); err != nil || !info.IsDir() {
		t.Fatalf("managed Workspace directory was not created: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docsRoot, "preserved.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	updated, err := svc.UpdateAdminWorkspace(context.Background(), "project", domain.WorkspaceInput{ID: "project", Access: "read_only"}, "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Access != "read_only" {
		t.Fatalf("workspace access was not updated: %#v", updated)
	}
	if _, err := svc.UploadWorkspaceFile(context.Background(), "project", "blocked.txt", "blocked.txt", strings.NewReader("x"), "admin-web"); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("updated read-only permission was not enforced: %v", err)
	}
	if err := svc.DeleteAdminWorkspace(context.Background(), "docs", "admin-web"); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.workspaceByID("docs"); ok {
		t.Fatal("removed workspace remains active")
	}
	if _, err := os.Stat(filepath.Join(docsRoot, "preserved.txt")); err != nil {
		t.Fatalf("removing registration deleted Workspace data: %v", err)
	}
	if _, err := svc.CreateAdminWorkspace(context.Background(), domain.WorkspaceInput{ID: "docs", Access: "read_write"}, "admin-web"); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(docsRoot, "preserved.txt")); err != nil || string(content) != "keep" {
		t.Fatalf("re-adding Workspace did not reuse its directory: %q err=%v", content, err)
	}
}

func TestWorkspaceManagedDirectoriesRejectUnsafeNamesAndSymlinks(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	for _, id := range []string{".", "..", "CON", "com1.txt", "trailing."} {
		if _, err := svc.CreateAdminWorkspace(context.Background(), domain.WorkspaceInput{ID: id, Access: "read_write"}, "admin-web"); err == nil {
			t.Fatalf("unsafe Workspace id %q was accepted", id)
		}
	}
	if _, err := svc.CreateAdminWorkspace(context.Background(), domain.WorkspaceInput{ID: "PROJECT", Access: "read_write"}, "admin-web"); err == nil {
		t.Fatal("case-insensitive duplicate Workspace id was accepted")
	}

	target := t.TempDir()
	linkedRoot := filepath.Join(filepath.Dir(root), "linked")
	if err := os.Symlink(target, linkedRoot); err != nil {
		t.Skipf("symbolic links are unavailable: %v", err)
	}
	if err := svc.InitializeWorkspaces(context.Background(), linkedRoot); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symlinked managed root was accepted: %v", err)
	}
	if _, err := svc.CreateAdminWorkspace(context.Background(), domain.WorkspaceInput{ID: "linked", Access: "read_write"}, "admin-web"); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("symlinked Workspace directory was accepted: %v", err)
	}
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
	pending, err := svc.EditWorkspaceFile(context.Background(), "project", "app.conf", "", patch, read.File.SHA256, "", "change port", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" {
		t.Fatalf("workspace write skipped approval: %#v", pending)
	}
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator")
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
	pending, err := svc.EditWorkspaceFile(context.Background(), "project", "app.conf", "", patch, stale, "", "change", "restore", "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator")
	if err == nil || result.ExitCode != 73 {
		t.Fatalf("expected conflict, got %#v err=%v", result, err)
	}
}

func TestWorkspaceFileEditReplacesAndCreatesFiles(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	existingPath := filepath.Join(root, "app.conf")
	if err := os.WriteFile(existingPath, []byte("enabled=false\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256([]byte("enabled=false\n")))
	pending, err := svc.EditWorkspaceFile(context.Background(), "project", "app.conf", "enabled=true\n", "", expected, "", "enable app", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(existingPath)
	if err != nil || string(content) != "enabled=true\n" {
		t.Fatalf("replacement content=%q err=%v", content, err)
	}
	info, err := os.Stat(existingPath)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("replacement mode=%v err=%v", info, err)
	}

	createdPath := filepath.Join(root, "new.conf")
	pending, err = svc.EditWorkspaceFile(context.Background(), "project", "new.conf", "created=true\n", "", "absent", "", "create config", "remove file", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator"); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(createdPath)
	if err != nil || string(content) != "created=true\n" {
		t.Fatalf("created content=%q err=%v", content, err)
	}
	info, err = os.Stat(createdPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created mode=%v err=%v", info, err)
	}
}

func TestWorkspaceFileEditRejectsAmbiguousChanges(t *testing.T) {
	svc, _ := newWorkspaceService(t, "read_write")
	expected := strings.Repeat("a", 64)
	if _, err := svc.EditWorkspaceFile(context.Background(), "project", "app.conf", "replacement", "@@ -0,0 +1 @@\n+patch\n", expected, "", "change", "restore", "test"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("content and patch were accepted together: %v", err)
	}
	if _, err := svc.EditWorkspaceFile(context.Background(), "project", "new.conf", "", "@@ -0,0 +1 @@\n+new\n", "absent", "", "create", "remove", "test"); err == nil || !strings.Contains(err.Error(), "cannot create") {
		t.Fatalf("patch creation was accepted: %v", err)
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
	pending, err := svc.EditWorkspaceFile(context.Background(), "project", "app.conf", "", patch, expected, "fixture", "change port", "restore backup", "test")
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed", "operator")
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
	if len(capabilities) != 1 || capabilities[0].ID != "project" {
		t.Fatalf("unexpected admin capabilities: %#v", capabilities)
	}
	preview, err := svc.PreviewAdminWorkspaceFile("project", "main.go")
	if err != nil {
		t.Fatal(err)
	}
	if preview.Path != "main.go" || preview.Content != string(content) || preview.SHA256 != wantSHA || preview.Binary || preview.Truncated {
		t.Fatalf("unexpected workspace preview: %#v", preview)
	}
	deleted, err := svc.DeleteAdminWorkspaceEntry(context.Background(), "project", "main.go", "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Path != "main.go" || deleted.Type != "file" || deleted.SHA256 != wantSHA {
		t.Fatalf("unexpected delete result: %#v", deleted)
	}
	if _, err := os.Stat(filepath.Join(root, "main.go")); !os.IsNotExist(err) {
		t.Fatalf("deleted file remains at its original path: %v", err)
	}
	listing, err = svc.ListAdminWorkspaceFiles("project", ".")
	if err != nil || len(listing.Entries) != 0 {
		t.Fatalf("deleted file remains in listing: %#v err=%v", listing, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".opspilot-trash")); !os.IsNotExist(err) {
		t.Fatalf("delete created a recovery directory: %v", err)
	}
}

func TestWorkspaceAdminDeletePermanentlyRemovesDirectory(t *testing.T) {
	svc, root := newWorkspaceService(t, "read_write")
	directory := filepath.Join(root, "build")
	if err := os.MkdirAll(filepath.Join(directory, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "assets", "app.js"), []byte("console.log('ok')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deleted, err := svc.DeleteAdminWorkspaceEntry(context.Background(), "project", "build", "admin-web")
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Path != "build" || deleted.Type != "directory" || deleted.Size != 0 || deleted.SHA256 != "" {
		t.Fatalf("unexpected directory delete result: %#v", deleted)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("deleted directory remains at its original path: %v", err)
	}
	if _, err := svc.DeleteAdminWorkspaceEntry(context.Background(), "project", ".", "admin-web"); err == nil || !strings.Contains(err.Error(), "root cannot be deleted") {
		t.Fatalf("Workspace root deletion was accepted: %v", err)
	}
}

func TestWorkspaceUploadRejectsReadOnlyWorkspace(t *testing.T) {
	svc, _ := newWorkspaceService(t, "read_only")
	if _, err := svc.UploadWorkspaceFile(context.Background(), "project", "file.txt", "file.txt", bytes.NewBufferString("x"), "admin-web"); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("read-only Workspace accepted upload: %v", err)
	}
	if _, err := svc.DeleteAdminWorkspaceEntry(context.Background(), "project", "file.txt", "admin-web"); err == nil || !strings.Contains(err.Error(), "read_only") {
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
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed exact source and destination", "operator")
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
	if _, err := svc.Approve(context.Background(), stale.ApprovalID, "reviewed before source changed", "operator"); err == nil || !strings.Contains(err.Error(), "version conflict") {
		t.Fatalf("changed Workspace source was uploaded after approval: %v", err)
	}
	if len(transport.calls) != 1 {
		t.Fatalf("version-conflicted source reached transport: %#v", transport.calls)
	}
}

func TestWorkspaceShellRunsInApprovalGatedSandbox(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap is not installed")
	}
	svc, root := newWorkspaceService(t, "read_write")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("WORKSPACE_SECRET=must-not-leak\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunWorkspaceShell(context.Background(), "project", "pwd", "../", nil, 10, "invalid traversal", "none", "none", "test"); err == nil || !strings.Contains(err.Error(), "clean and relative") {
		t.Fatalf("workspace shell traversal cwd was not rejected before approval: %v", err)
	}

	pending, err := svc.RunWorkspaceShell(context.Background(), "project", "test ! -e /home/pig\npwd\nmkdir -p extracted\nprintf 'ready\\n' > extracted/value.txt\ncat .env || true\n", ".", nil, 10, "extract a release archive", "create extracted files", "remove extracted", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" || pending.Risk != domain.RiskChange {
		t.Fatalf("workspace shell skipped exact approval: %#v", pending)
	}
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed sandboxed extraction", "operator")
	if err != nil || approved.Status != "completed" {
		t.Fatalf("workspace shell failed: %#v err=%v", approved, err)
	}
	if !strings.Contains(approved.Stdout, "/workspace") || strings.Contains(approved.Stdout, root) || strings.Contains(approved.Stdout, "must-not-leak") {
		t.Fatalf("workspace shell exposed a host path or sensitive file: %q", approved.Stdout)
	}
	content, err := os.ReadFile(filepath.Join(root, "extracted", "value.txt"))
	if err != nil || string(content) != "ready\n" {
		t.Fatalf("workspace shell output was not persisted: %q err=%v", content, err)
	}
}

func TestWorkspaceShellFailsClosedWithoutSandbox(t *testing.T) {
	svc, _ := newWorkspaceService(t, "read_write")
	svc.workspaceSandboxPath = filepath.Join(t.TempDir(), "missing-bwrap")
	capabilities := svc.ListWorkspaceCapabilities()
	if len(capabilities) != 1 || capabilities[0].Shell {
		t.Fatalf("unavailable sandbox was advertised: %#v", capabilities)
	}
	if _, err := svc.RunWorkspaceShell(context.Background(), "project", "pwd", ".", nil, 10, "inspect workspace", "none", "none", "test"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("workspace shell did not fail closed: %v", err)
	}
}

func TestReadOnlyWorkspaceShellCannotPersistChanges(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap is not installed")
	}
	svc, root := newWorkspaceService(t, "read_only")
	pending, err := svc.RunWorkspaceShell(context.Background(), "project", "printf 'blocked\\n' > created.txt", ".", nil, 10, "verify read-only mount", "none", "none", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" {
		t.Fatalf("workspace shell skipped approval: %#v", pending)
	}
	result, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed read-only test", "operator")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "failed" || result.ExitCode == 0 {
		t.Fatalf("read-only workspace accepted a write: %#v", result)
	}
	if _, statErr := os.Stat(filepath.Join(root, "created.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("read-only workspace persisted shell output: %v", statErr)
	}
}

func TestHostWorkspaceShellRequiresFreshOneTimeApproval(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	svc, root := newWorkspaceService(t, "read_write")
	mode := domain.WorkspaceShellModeHost
	if _, err := svc.SaveSystemSettings(context.Background(), domain.SystemSettingsInput{
		AgentMaxIterations: domain.DefaultAgentMaxIterations, WorkspaceShellMode: &mode,
	}, "test"); err != nil {
		t.Fatal(err)
	}
	ctx := WithSessionID(context.Background(), "host-shell-session")
	pending, err := svc.RunWorkspaceShell(ctx, "project", "pwd\nprintf 'ok\\n' > host-created.txt", ".", nil, 10, "exercise host shell", "create a fixture", "remove fixture", "test")
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "approval_required" || !containsString(pending.PolicyHits, "workspace_host_shell") {
		t.Fatalf("host shell did not request explicit approval: %#v", pending)
	}
	if _, err := svc.ApproveWithScope(context.Background(), pending.ApprovalID, "reviewed", "session", "operator"); err == nil || !strings.Contains(err.Error(), "one-time approval") {
		t.Fatalf("host shell accepted session approval: %v", err)
	}
	approved, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed once", "operator")
	if err != nil || approved.Status != "completed" {
		t.Fatalf("one-time host shell approval failed: %#v err=%v", approved, err)
	}
	if strings.Contains(approved.Stdout, root) || !strings.Contains(approved.Stdout, "$WORKSPACE") {
		t.Fatalf("host shell exposed the workspace root: %q", approved.Stdout)
	}
	if content, err := os.ReadFile(filepath.Join(root, "host-created.txt")); err != nil || string(content) != "ok\n" {
		t.Fatalf("host shell did not write the workspace fixture: content=%q err=%v", content, err)
	}
	repeated, err := svc.RunWorkspaceShell(ctx, "project", "pwd\nprintf 'ok\\n' > host-created.txt", ".", nil, 10, "exercise host shell", "create a fixture", "remove fixture", "test")
	if err != nil || repeated.Status != "approval_required" {
		t.Fatalf("repeated host shell reused approval: %#v err=%v", repeated, err)
	}
}

func TestHostWorkspaceShellRejectsReadOnlyDisabledAndBackendSwitch(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	readOnlyService, _ := newWorkspaceService(t, "read_only")
	hostMode := domain.WorkspaceShellModeHost
	if _, err := readOnlyService.SaveSystemSettings(context.Background(), domain.SystemSettingsInput{
		AgentMaxIterations: domain.DefaultAgentMaxIterations, WorkspaceShellMode: &hostMode,
	}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := readOnlyService.RunWorkspaceShell(context.Background(), "project", "pwd", ".", nil, 10, "inspect", "none", "none", "test"); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("read_only workspace accepted host shell: %v", err)
	}

	svc, _ := newWorkspaceService(t, "read_write")
	if _, err := svc.SaveSystemSettings(context.Background(), domain.SystemSettingsInput{
		AgentMaxIterations: domain.DefaultAgentMaxIterations, WorkspaceShellMode: &hostMode,
	}, "test"); err != nil {
		t.Fatal(err)
	}
	pending, err := svc.RunWorkspaceShell(context.Background(), "project", "pwd", ".", nil, 10, "inspect", "none", "none", "test")
	if err != nil {
		t.Fatal(err)
	}
	disabledMode := domain.WorkspaceShellModeDisabled
	if _, err := svc.SaveSystemSettings(context.Background(), domain.SystemSettingsInput{
		AgentMaxIterations: domain.DefaultAgentMaxIterations, WorkspaceShellMode: &disabledMode,
	}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(context.Background(), pending.ApprovalID, "reviewed before setting changed", "operator"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("approved host shell ran after backend was disabled: %v", err)
	}
	if _, err := svc.RunWorkspaceShell(context.Background(), "project", "pwd", ".", nil, 10, "inspect", "none", "none", "test"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled workspace shell created an approval: %v", err)
	}
}

func TestWorkspaceShellBackendValidation(t *testing.T) {
	limits := config.Default().Limits
	for _, req := range []domain.ExecRequest{
		{Mode: domain.ExecWorkspaceShell, WorkspaceID: "project", Script: "pwd"},
		{Mode: domain.ExecWorkspaceShell, WorkspaceID: "project", WorkspaceShellBackend: "automatic", Script: "pwd"},
		{Mode: domain.ExecProgram, Program: "pwd", WorkspaceShellBackend: domain.WorkspaceShellModeHost},
	} {
		if err := validateRequestLimits(req, limits, nil); err == nil {
			t.Fatalf("invalid workspace shell backend fields were accepted: %#v", req)
		}
	}
	valid := domain.ExecRequest{
		Mode: domain.ExecWorkspaceShell, WorkspaceID: "project",
		WorkspaceShellBackend: domain.WorkspaceShellModeSandbox, Script: "pwd", Cwd: ".",
	}
	if err := validateRequestLimits(valid, limits, nil); err != nil {
		t.Fatalf("valid workspace shell backend was rejected: %v", err)
	}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
