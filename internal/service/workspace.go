package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/ids"
	"eino-ops-agent/internal/sshx"
)

type WorkspaceCapability struct {
	ID         string   `json:"id"`
	Access     string   `json:"access"`
	Validators []string `json:"validators,omitempty"`
}

type AdminWorkspaceCapability struct {
	WorkspaceCapability
	Root string `json:"root"`
}

type WorkspaceUploadResult struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

type WorkspaceFileEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
}

type WorkspaceFileList struct {
	WorkspaceID string               `json:"workspace_id"`
	Path        string               `json:"path"`
	Entries     []WorkspaceFileEntry `json:"entries"`
	Truncated   bool                 `json:"truncated,omitempty"`
}

type WorkspaceFilePreview struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	Content     string `json:"content,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
	Binary      bool   `json:"binary,omitempty"`
}

type WorkspaceDeleteResult struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	TrashID     string `json:"trash_id"`
	Recoverable bool   `json:"recoverable"`
}

const maxWorkspaceUploadBytes = 100 << 20

func (s *Service) ListWorkspaceCapabilities() []WorkspaceCapability {
	result := make([]WorkspaceCapability, 0, len(s.workspaces))
	for _, workspace := range s.workspaces {
		item := WorkspaceCapability{ID: workspace.ID, Access: workspace.Access}
		for _, validator := range s.validators {
			if validator.Scope == "workspace" {
				item.Validators = append(item.Validators, validator.ID)
			}
		}
		sort.Strings(item.Validators)
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func (s *Service) ListAdminWorkspaceCapabilities() []AdminWorkspaceCapability {
	public := s.ListWorkspaceCapabilities()
	result := make([]AdminWorkspaceCapability, 0, len(public))
	for _, capability := range public {
		workspace := s.workspaces[capability.ID]
		result = append(result, AdminWorkspaceCapability{WorkspaceCapability: capability, Root: workspace.Root})
	}
	return result
}

func (s *Service) ListAdminWorkspaceFiles(workspaceID, relativePath string) (WorkspaceFileList, error) {
	workspace, ok := s.workspaces[strings.TrimSpace(workspaceID)]
	if !ok {
		return WorkspaceFileList{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	relativePath = strings.TrimSpace(relativePath)
	if relativePath == "" {
		relativePath = "."
	}
	directory, err := s.resolveWorkspacePath(workspace, relativePath, false)
	if err != nil {
		return WorkspaceFileList{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return WorkspaceFileList{}, err
	}
	result := WorkspaceFileList{WorkspaceID: workspace.ID, Path: relativePath, Entries: make([]WorkspaceFileEntry, 0, min(len(entries), 200))}
	for _, entry := range entries {
		if len(result.Entries) == 200 {
			result.Truncated = true
			break
		}
		if entry.Type()&os.ModeSymlink != 0 || isSensitiveWorkspaceComponent(entry.Name()) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		kind := "file"
		if entry.IsDir() {
			kind = "directory"
		} else if !info.Mode().IsRegular() {
			continue
		}
		result.Entries = append(result.Entries, WorkspaceFileEntry{Name: entry.Name(), Type: kind, Size: info.Size()})
	}
	sort.Slice(result.Entries, func(i, j int) bool {
		if result.Entries[i].Type != result.Entries[j].Type {
			return result.Entries[i].Type == "directory"
		}
		return strings.ToLower(result.Entries[i].Name) < strings.ToLower(result.Entries[j].Name)
	})
	return result, nil
}

func (s *Service) PreviewAdminWorkspaceFile(workspaceID, relativePath string) (WorkspaceFilePreview, error) {
	workspace, ok := s.workspaces[strings.TrimSpace(workspaceID)]
	if !ok {
		return WorkspaceFilePreview{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	relativePath = strings.TrimSpace(relativePath)
	path, err := s.resolveWorkspacePath(workspace, relativePath, false)
	if err != nil {
		return WorkspaceFilePreview{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return WorkspaceFilePreview{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return WorkspaceFilePreview{}, fmt.Errorf("workspace preview target is not a regular file")
	}
	const previewLimit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, previewLimit+1))
	if err != nil {
		return WorkspaceFilePreview{}, err
	}
	truncated := len(data) > previewLimit
	if truncated {
		data = data[:previewLimit]
	}
	digest := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return WorkspaceFilePreview{}, err
	}
	if _, err := io.Copy(digest, file); err != nil {
		return WorkspaceFilePreview{}, err
	}
	binary := bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data)
	result := WorkspaceFilePreview{
		WorkspaceID: workspace.ID, Path: relativePath, Size: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil)),
		Truncated: truncated, Binary: binary,
	}
	if !binary {
		result.Content = string(data)
	}
	return result, nil
}

func (s *Service) DeleteAdminWorkspaceFile(ctx context.Context, workspaceID, relativePath, actor string) (WorkspaceDeleteResult, error) {
	workspace, ok := s.workspaces[strings.TrimSpace(workspaceID)]
	if !ok {
		return WorkspaceDeleteResult{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	if workspace.Access != "read_write" {
		return WorkspaceDeleteResult{}, fmt.Errorf("workspace %q is read_only", workspace.ID)
	}
	relativePath = strings.TrimSpace(relativePath)
	path, err := s.resolveWorkspacePath(workspace, relativePath, false)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	if !info.Mode().IsRegular() {
		return WorkspaceDeleteResult{}, fmt.Errorf("only regular Workspace files can be deleted from Web")
	}
	file, err := os.Open(path)
	if err != nil {
		return WorkspaceDeleteResult{}, err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if copyErr != nil {
		return WorkspaceDeleteResult{}, copyErr
	}
	if closeErr != nil {
		return WorkspaceDeleteResult{}, closeErr
	}
	trashDirectory := filepath.Join(workspace.Root, ".opspilot-trash")
	if trashInfo, err := os.Lstat(trashDirectory); err == nil {
		if trashInfo.Mode()&os.ModeSymlink != 0 || !trashInfo.IsDir() {
			return WorkspaceDeleteResult{}, fmt.Errorf("Workspace recovery directory is invalid")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return WorkspaceDeleteResult{}, err
	} else if err := os.Mkdir(trashDirectory, 0o700); err != nil {
		return WorkspaceDeleteResult{}, err
	}
	trashID := ids.New("deleted")
	trashPath := filepath.Join(trashDirectory, trashID)
	if err := os.Rename(path, trashPath); err != nil {
		return WorkspaceDeleteResult{}, err
	}
	if err := syncLocalDirectory(filepath.Dir(path)); err != nil {
		_ = os.Rename(trashPath, path)
		return WorkspaceDeleteResult{}, err
	}
	if err := syncLocalDirectory(trashDirectory); err != nil {
		_ = os.Rename(trashPath, path)
		return WorkspaceDeleteResult{}, err
	}
	result := WorkspaceDeleteResult{
		WorkspaceID: workspace.ID, Path: relativePath, Size: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil)), TrashID: trashID, Recoverable: true,
	}
	s.audit(ctx, "", "workspace_file_deleted", actor, map[string]any{
		"workspace_id": workspace.ID, "path": relativePath, "size": info.Size(), "sha256": result.SHA256, "trash_id": trashID, "recoverable": true,
	})
	return result, nil
}

func (s *Service) UploadWorkspaceFile(ctx context.Context, workspaceID, targetPath, originalFilename string, source io.Reader, actor string) (WorkspaceUploadResult, error) {
	workspace, ok := s.workspaces[strings.TrimSpace(workspaceID)]
	if !ok {
		return WorkspaceUploadResult{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	if workspace.Access != "read_write" {
		return WorkspaceUploadResult{}, fmt.Errorf("workspace %q is read_only", workspace.ID)
	}
	targetPath = strings.TrimSpace(targetPath)
	if targetPath == "" {
		targetPath = filepath.Base(strings.ReplaceAll(originalFilename, "\\", "/"))
	}
	if targetPath == "" || targetPath == "." || len(targetPath) > 1024 {
		return WorkspaceUploadResult{}, fmt.Errorf("invalid workspace upload path")
	}
	target, err := s.resolveWorkspacePath(workspace, targetPath, true)
	if err != nil {
		return WorkspaceUploadResult{}, err
	}
	if _, err := os.Lstat(target); err == nil {
		return WorkspaceUploadResult{}, fmt.Errorf("workspace file already exists; choose a new path instead of overwriting it")
	} else if !errors.Is(err, os.ErrNotExist) {
		return WorkspaceUploadResult{}, err
	}
	parent := filepath.Dir(target)
	parentInfo, err := os.Stat(parent)
	if err != nil || !parentInfo.IsDir() {
		return WorkspaceUploadResult{}, fmt.Errorf("workspace upload parent directory does not exist")
	}
	temporary, err := os.CreateTemp(parent, ".opspilot-upload-*")
	if err != nil {
		return WorkspaceUploadResult{}, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(source, maxWorkspaceUploadBytes+1))
	if copyErr != nil {
		temporary.Close()
		return WorkspaceUploadResult{}, copyErr
	}
	if written > maxWorkspaceUploadBytes {
		temporary.Close()
		return WorkspaceUploadResult{}, fmt.Errorf("workspace upload exceeds 100 MiB")
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return WorkspaceUploadResult{}, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return WorkspaceUploadResult{}, err
	}
	if err := temporary.Close(); err != nil {
		return WorkspaceUploadResult{}, err
	}
	if err := os.Link(temporaryPath, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return WorkspaceUploadResult{}, fmt.Errorf("workspace file already exists; choose a new path instead of overwriting it")
		}
		return WorkspaceUploadResult{}, err
	}
	if err := syncLocalDirectory(parent); err != nil {
		_ = os.Remove(target)
		return WorkspaceUploadResult{}, err
	}
	result := WorkspaceUploadResult{WorkspaceID: workspace.ID, Path: targetPath, Size: written, SHA256: hex.EncodeToString(digest.Sum(nil))}
	s.audit(ctx, "", "workspace_file_uploaded", actor, map[string]any{
		"workspace_id": workspace.ID, "path": targetPath, "size": written, "sha256": result.SHA256,
	})
	return result, nil
}

func (s *Service) ReadWorkspaceFile(ctx context.Context, workspaceID, relativePath string, maxBytes int, offset int64, actor string) (domain.ExecResult, error) {
	host, err := s.workspaceHost(ctx, workspaceID)
	if err != nil {
		return domain.ExecResult{}, err
	}
	if maxBytes <= 0 || maxBytes > s.limits.ModelOutputBytes {
		maxBytes = s.limits.ModelOutputBytes
	}
	result, err := s.Submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecWorkspaceRead, WorkspaceID: workspaceID, RelativePath: relativePath,
		MaxBytes: maxBytes, OffsetBytes: offset, Reason: "read a bounded file from an allowlisted workspace",
	}, actor)
	metadata, content := parseFileReadOutput(relativePath, result.Stdout)
	metadata.OffsetBytes = offset
	metadata.ReturnedBytes = len(content)
	metadata.Sensitive = strings.Contains(content, "[REDACTED]")
	result.File, result.Stdout = &metadata, content
	return result, err
}

func (s *Service) ListWorkspaceFiles(ctx context.Context, workspaceID, relativePath, actor string) (domain.ExecResult, error) {
	host, err := s.workspaceHost(ctx, workspaceID)
	if err != nil {
		return domain.ExecResult{}, err
	}
	return s.Submit(ctx, domain.ExecRequest{HostID: host.ID, Mode: domain.ExecWorkspaceList, WorkspaceID: workspaceID, RelativePath: relativePath, Reason: "list an allowlisted workspace directory"}, actor)
}

func (s *Service) SearchWorkspace(ctx context.Context, workspaceID, relativePath, pattern string, maxMatches int, actor string) (domain.ExecResult, error) {
	host, err := s.workspaceHost(ctx, workspaceID)
	if err != nil {
		return domain.ExecResult{}, err
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || len(pattern) > 512 || strings.ContainsAny(pattern, "\x00\r\n") {
		return domain.ExecResult{}, fmt.Errorf("invalid workspace search pattern")
	}
	if maxMatches <= 0 || maxMatches > 200 {
		maxMatches = 100
	}
	return s.Submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecWorkspaceSearch, WorkspaceID: workspaceID, RelativePath: relativePath,
		SearchPattern: pattern, MaxBytes: maxMatches, Reason: "search literal text in an allowlisted workspace file",
	}, actor)
}

func (s *Service) ApplyWorkspacePatch(ctx context.Context, workspaceID, relativePath, patchContent, expectedSHA256, validatorID, reason, rollback, actor string) (domain.ExecResult, error) {
	workspace, ok := s.workspaces[workspaceID]
	if !ok {
		return domain.ExecResult{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	if workspace.Access != "read_write" {
		return domain.ExecResult{}, fmt.Errorf("workspace %q is read_only", workspaceID)
	}
	if !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(expectedSHA256) {
		return domain.ExecResult{}, fmt.Errorf("expected_sha256 is required for workspace patches")
	}
	if strings.TrimSpace(patchContent) == "" || len(patchContent) > 1<<20 || strings.Contains(patchContent, "[REDACTED]") || s.redactor.Redact(patchContent) != patchContent {
		return domain.ExecResult{}, fmt.Errorf("workspace patch is empty, too large, or contains sensitive content")
	}
	if _, err := s.workspaceValidator(validatorID, workspace, relativePath); err != nil {
		return domain.ExecResult{}, err
	}
	host, err := s.workspaceHost(ctx, workspaceID)
	if err != nil {
		return domain.ExecResult{}, err
	}
	result, submitErr := s.Submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecWorkspacePatch, WorkspaceID: workspaceID, RelativePath: relativePath,
		Script: patchContent, ExpectedSHA256: strings.ToLower(expectedSHA256), Validator: validatorID,
		Reason: reason, ExpectedChanges: "transactionally patch workspace file " + relativePath, Rollback: rollback,
	}, actor)
	metadata := parseConfigTransactionOutput(relativePath, validatorID, result.Stdout)
	result.File = &metadata
	if result.ExitCode == 73 {
		return result, fmt.Errorf("conflict: workspace file changed after it was read")
	}
	if result.ExitCode == 74 {
		return result, fmt.Errorf("workspace validation failed; the previous file was restored")
	}
	if submitErr == nil && result.Status == "completed" {
		operation := domain.FileOperation{ID: ids.New("fileop"), RunID: result.RunID, HostID: host.ID, Path: relativePath,
			BackupPath: metadata.BackupPath, BeforeSHA256: metadata.BeforeSHA256, AfterSHA256: metadata.SHA256,
			Validator: validatorID, Status: "completed", CreatedAt: time.Now().UTC()}
		if err := s.store.CreateFileOperation(ctx, operation); err != nil {
			return result, err
		}
		result.File.OperationID = operation.ID
		result.Message = "workspace file operation " + operation.ID + " completed"
	}
	return result, submitErr
}

// UploadWorkspaceFileToHost transfers one allowlisted Workspace file directly
// to a registered host. The model provides only the Workspace-relative path;
// the absolute local path is resolved after approval and is never serialized.
func (s *Service) UploadWorkspaceFileToHost(ctx context.Context, hostID, workspaceID, relativePath, expectedSHA256, remotePath, reason, rollback, actor string) (domain.ExecResult, error) {
	return s.Submit(ctx, domain.ExecRequest{
		HostID: hostID, Mode: domain.ExecWorkspaceUpload, WorkspaceID: workspaceID, RelativePath: relativePath,
		ExpectedSHA256: strings.ToLower(strings.TrimSpace(expectedSHA256)), RemotePath: remotePath, Reason: reason,
		ExpectedChanges: "upload Workspace file to " + remotePath, Rollback: rollback,
	}, actor)
}

func (s *Service) prepareWorkspaceUpload(req domain.ExecRequest) (domain.ExecRequest, error) {
	workspace, ok := s.workspaces[strings.TrimSpace(req.WorkspaceID)]
	if !ok {
		return req, fmt.Errorf("workspace %q not found", req.WorkspaceID)
	}
	expected := strings.ToLower(strings.TrimSpace(req.ExpectedSHA256))
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(expected) {
		return req, fmt.Errorf("workspace upload requires the expected_sha256 returned by workspace_file_read")
	}
	path, err := s.resolveWorkspacePath(workspace, strings.TrimSpace(req.RelativePath), false)
	if err != nil {
		return req, err
	}
	file, err := os.Open(path)
	if err != nil {
		return req, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return req, fmt.Errorf("workspace upload source is not a regular file")
	}
	digest := sha256.New()
	written, copyErr := io.Copy(digest, io.LimitReader(file, maxWorkspaceUploadBytes+1))
	closeErr := file.Close()
	if copyErr != nil {
		return req, copyErr
	}
	if closeErr != nil {
		return req, closeErr
	}
	if written > maxWorkspaceUploadBytes {
		return req, fmt.Errorf("workspace upload source exceeds 100 MiB")
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != expected {
		return req, fmt.Errorf("workspace upload source version conflict: expected SHA256 %s, got %s", expected, actual)
	}
	req.ExpectedSHA256 = expected
	req.LocalPath = path
	return req, nil
}

func isWorkspaceMode(mode domain.ExecMode) bool {
	switch mode {
	case domain.ExecWorkspaceRead, domain.ExecWorkspaceList, domain.ExecWorkspaceSearch, domain.ExecWorkspacePatch:
		return true
	default:
		return false
	}
}

func (s *Service) executeWorkspace(ctx context.Context, req domain.ExecRequest) (sshx.RawResult, error) {
	started := time.Now()
	workspace, ok := s.workspaces[req.WorkspaceID]
	if !ok {
		return sshx.RawResult{}, fmt.Errorf("workspace %q not found", req.WorkspaceID)
	}
	path, err := s.resolveWorkspacePath(workspace, req.RelativePath, req.Mode == domain.ExecWorkspacePatch)
	if err != nil {
		return sshx.RawResult{}, err
	}
	result := sshx.RawResult{ExitCode: 0}
	switch req.Mode {
	case domain.ExecWorkspaceRead:
		result.Stdout, err = readWorkspaceFile(path, req.RelativePath, req.MaxBytes, req.OffsetBytes)
	case domain.ExecWorkspaceList:
		result.Stdout, err = listWorkspaceDirectory(path)
	case domain.ExecWorkspaceSearch:
		result.Stdout, err = searchWorkspaceFile(path, req.SearchPattern, req.MaxBytes)
	case domain.ExecWorkspacePatch:
		if workspace.Access != "read_write" {
			err = fmt.Errorf("workspace %q is read_only", workspace.ID)
			break
		}
		result, err = s.patchWorkspaceFile(ctx, workspace, path, req)
	default:
		err = fmt.Errorf("unsupported workspace operation %q", req.Mode)
	}
	result.Duration = time.Since(started)
	result.Stdout = []byte(strings.ReplaceAll(string(result.Stdout), workspace.Root, "$WORKSPACE"))
	result.Stderr = []byte(strings.ReplaceAll(string(result.Stderr), workspace.Root, "$WORKSPACE"))
	if err != nil && result.ExitCode == 0 {
		result.ExitCode = 1
		result.Stderr = []byte(strings.ReplaceAll(err.Error(), workspace.Root, "$WORKSPACE"))
	}
	if err != nil {
		err = fmt.Errorf("%s", strings.ReplaceAll(err.Error(), workspace.Root, "$WORKSPACE"))
	}
	return result, err
}

func (s *Service) workspaceHost(ctx context.Context, workspaceID string) (domain.Host, error) {
	_, ok := s.workspaces[workspaceID]
	if !ok {
		return domain.Host{}, fmt.Errorf("workspace %q not found", workspaceID)
	}
	digest := sha256.Sum256([]byte(workspaceID))
	id := "workspace_" + hex.EncodeToString(digest[:8])
	if host, err := s.store.GetHost(ctx, id); err == nil {
		return host, nil
	}
	now := time.Now().UTC()
	return s.store.UpsertHost(ctx, domain.Host{ID: id, Name: "Workspace / " + workspaceID, Address: "local-workspace", Port: 1, User: "opspilot", AuthType: "workspace", SudoMode: "none", CreatedAt: now})
}

func (s *Service) resolveWorkspacePath(workspace config.Workspace, relative string, allowMissing bool) (string, error) {
	if relative == "" {
		relative = "."
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || strings.ContainsAny(relative, "\\\x00\r\n") {
		return "", fmt.Errorf("workspace path must be clean and relative")
	}
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if isSensitiveWorkspaceComponent(component) {
			return "", fmt.Errorf("workspace path is sensitive and denied")
		}
	}
	root, err := filepath.EvalSymlinks(workspace.Root)
	if err != nil {
		return "", fmt.Errorf("resolve workspace root: %w", err)
	}
	target := filepath.Join(root, relative)
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		if !allowMissing || !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent, parentErr := filepath.EvalSymlinks(filepath.Dir(target))
		if parentErr != nil {
			return "", parentErr
		}
		resolved = filepath.Join(parent, filepath.Base(target))
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return "", fmt.Errorf("workspace path escapes its configured root")
	}
	if info, lstatErr := os.Lstat(target); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("workspace symbolic links are denied")
	}
	return resolved, nil
}

func readWorkspaceFile(path, displayPath string, maxBytes int, offset int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("workspace target is not a regular file")
	}
	if offset < 0 {
		return nil, fmt.Errorf("offset_bytes cannot be negative")
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)))
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.Copy(digest, file); err != nil {
		return nil, err
	}
	metadata := fmt.Sprintf("%s\n%d\t%o\t%s\t%s\t%d\n%x  %s\n%s\n", fileMetaMarker, info.Size(), info.Mode().Perm(), "local", "local", info.ModTime().Unix(), digest.Sum(nil), displayPath, fileContentMarker)
	return append([]byte(metadata), content...), nil
}

func listWorkspaceDirectory(path string) ([]byte, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	type item struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Size int64  `json:"size,omitempty"`
	}
	result := make([]item, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || isSensitiveWorkspaceComponent(entry.Name()) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		kind := "file"
		if entry.IsDir() {
			kind = "directory"
		}
		result = append(result, item{Name: entry.Name(), Type: kind, Size: info.Size()})
	}
	return json.Marshal(map[string]any{"entries": result})
}

func isSensitiveWorkspaceComponent(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, ".env") || strings.HasPrefix(lower, ".opspilot-") || lower == ".ssh" || lower == ".data" || lower == "master.key" || strings.Contains(lower, "credential")
}

func searchWorkspaceFile(path, pattern string, maxMatches int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 10<<20))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var output strings.Builder
	line := 0
	matches := 0
	for scanner.Scan() {
		line++
		if strings.Contains(scanner.Text(), pattern) {
			fmt.Fprintf(&output, "%d:%s\n", line, scanner.Text())
			matches++
			if matches >= maxMatches {
				break
			}
		}
	}
	return []byte(output.String()), scanner.Err()
}

func (s *Service) patchWorkspaceFile(ctx context.Context, workspace config.Workspace, path string, req domain.ExecRequest) (sshx.RawResult, error) {
	started := time.Now()
	original, err := os.ReadFile(path)
	if err != nil {
		return sshx.RawResult{}, err
	}
	digest := sha256.Sum256(original)
	before := hex.EncodeToString(digest[:])
	if before != strings.ToLower(req.ExpectedSHA256) {
		return sshx.RawResult{ExitCode: 73, Stderr: []byte("workspace file version conflict"), Duration: time.Since(started)}, fmt.Errorf("workspace file version conflict")
	}
	updated, err := applyUnifiedPatch(string(original), req.Script)
	if err != nil {
		return sshx.RawResult{ExitCode: 1, Stderr: []byte(err.Error()), Duration: time.Since(started)}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return sshx.RawResult{}, err
	}
	suffix := time.Now().UTC().Format("20060102T150405Z") + "-" + ids.New("file")
	backup := filepath.Join(filepath.Dir(path), ".opspilot-"+filepath.Base(path)+"-"+suffix+".bak")
	temporary := filepath.Join(filepath.Dir(path), ".opspilot-"+filepath.Base(path)+"-"+suffix+".tmp")
	if err := writeSyncedFile(backup, original, 0o600); err != nil {
		return sshx.RawResult{}, err
	}
	if err := writeSyncedFile(temporary, []byte(updated), info.Mode().Perm()); err != nil {
		return sshx.RawResult{}, err
	}
	defer os.Remove(temporary)
	validationOutput, err := s.runWorkspaceValidator(ctx, req.Validator, workspace, req.RelativePath, temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return sshx.RawResult{ExitCode: 74, Stdout: validationOutput, Stderr: []byte(err.Error()), Duration: time.Since(started)}, err
	}
	if err := os.Rename(temporary, path); err != nil {
		return sshx.RawResult{}, err
	}
	if err := syncLocalDirectory(filepath.Dir(path)); err != nil {
		restoreErr := replaceLocalFile(backup, path, info.Mode().Perm())
		if restoreErr != nil {
			err = fmt.Errorf("sync changed workspace directory: %w; automatic rollback failed: %v", err, restoreErr)
		}
		return sshx.RawResult{ExitCode: 74, Stderr: []byte(err.Error()), Duration: time.Since(started)}, err
	}
	postOutput, err := s.runWorkspaceValidator(ctx, req.Validator, workspace, req.RelativePath, path)
	validationOutput = append(validationOutput, postOutput...)
	if err != nil {
		restoreErr := replaceLocalFile(backup, path, info.Mode().Perm())
		if restoreErr != nil {
			err = fmt.Errorf("%w; automatic rollback failed: %v", err, restoreErr)
		}
		return sshx.RawResult{ExitCode: 74, Stdout: validationOutput, Stderr: []byte(err.Error()), Duration: time.Since(started)}, err
	}
	afterDigest := sha256.Sum256([]byte(updated))
	stdout := fmt.Sprintf("%s\n%s  %s\n%s\n%s\n%s\n%s\n%x  %s\n", fileBeforeMarker, before, req.RelativePath, fileBackupMarker, filepath.Base(backup), fileValidationMarker, fileAfterMarker, afterDigest, req.RelativePath)
	stdout += string(validationOutput)
	return sshx.RawResult{ExitCode: 0, Stdout: []byte(stdout), Duration: time.Since(started)}, nil
}

func (s *Service) workspaceValidator(id string, workspace config.Workspace, relative string) (config.Validator, error) {
	if id == "" {
		return config.Validator{}, nil
	}
	validator, ok := s.validators[id]
	if !ok || validator.Scope != "workspace" {
		return config.Validator{}, fmt.Errorf("invalid workspace validator %q", id)
	}
	if !validatorAllowsPath(validator, filepath.Join(workspace.Root, relative)) && !validatorAllowsPath(validator, relative) {
		return config.Validator{}, fmt.Errorf("validator %q is not allowed for workspace path %s", id, relative)
	}
	return validator, nil
}

func (s *Service) runWorkspaceValidator(ctx context.Context, id string, workspace config.Workspace, relative, path string) ([]byte, error) {
	validator, err := s.workspaceValidator(id, workspace, relative)
	if err != nil || id == "" {
		return nil, err
	}
	args := make([]string, len(validator.Args))
	for index, argument := range validator.Args {
		args[index] = strings.ReplaceAll(argument, "{{path}}", path)
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(validator.TimeoutSeconds)*time.Second)
	defer cancel()
	command := exec.CommandContext(timeoutCtx, validator.Program, args...)
	command.Dir = workspace.Root
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	if output.Len() > s.limits.ModelOutputBytes {
		return output.Bytes()[:s.limits.ModelOutputBytes], err
	}
	return output.Bytes(), err
}

func copyLocalFile(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Chmod(mode); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func writeSyncedFile(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func replaceLocalFile(source, target string, mode os.FileMode) error {
	temporary := filepath.Join(filepath.Dir(target), ".opspilot-rollback-"+ids.New("file")+".tmp")
	if err := copyLocalFile(source, temporary, mode); err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncLocalDirectory(filepath.Dir(target))
}

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var hunkHeader = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

func applyUnifiedPatch(original, patchContent string) (string, error) {
	originalTrailingNewline := strings.HasSuffix(original, "\n")
	var originalLines []string
	if original != "" {
		originalLines = strings.Split(strings.TrimSuffix(original, "\n"), "\n")
	}
	patchLines := strings.Split(patchContent, "\n")
	result := make([]string, 0, len(originalLines))
	originalIndex := 0
	seenHunk := false
	for index := 0; index < len(patchLines); {
		match := hunkHeader.FindStringSubmatch(patchLines[index])
		if match == nil {
			index++
			continue
		}
		seenHunk = true
		oldStart, _ := strconv.Atoi(match[1])
		oldCount := patchHunkCount(match[2])
		newCount := patchHunkCount(match[4])
		targetIndex := oldStart - 1
		if oldStart == 0 && oldCount == 0 {
			targetIndex = 0
		}
		if targetIndex < originalIndex || targetIndex > len(originalLines) {
			return "", fmt.Errorf("patch hunk has an invalid original line")
		}
		result = append(result, originalLines[originalIndex:targetIndex]...)
		originalIndex = targetIndex
		oldConsumed, newProduced := 0, 0
		index++
		for index < len(patchLines) && !strings.HasPrefix(patchLines[index], "@@ ") {
			line := patchLines[index]
			if line == "\\ No newline at end of file" || (line == "" && index == len(patchLines)-1) {
				index++
				continue
			}
			if len(line) == 0 {
				return "", fmt.Errorf("invalid empty patch line")
			}
			switch line[0] {
			case ' ':
				if originalIndex >= len(originalLines) || originalLines[originalIndex] != line[1:] {
					return "", fmt.Errorf("patch context does not match current file")
				}
				result = append(result, originalLines[originalIndex])
				originalIndex++
				oldConsumed++
				newProduced++
			case '-':
				if originalIndex >= len(originalLines) || originalLines[originalIndex] != line[1:] {
					return "", fmt.Errorf("patch deletion does not match current file")
				}
				originalIndex++
				oldConsumed++
			case '+':
				result = append(result, line[1:])
				newProduced++
			default:
				return "", fmt.Errorf("invalid unified diff line")
			}
			index++
		}
		if oldConsumed != oldCount || newProduced != newCount {
			return "", fmt.Errorf("patch hunk line counts do not match its header")
		}
	}
	if !seenHunk {
		return "", fmt.Errorf("patch contains no unified diff hunks")
	}
	result = append(result, originalLines[originalIndex:]...)
	updated := strings.Join(result, "\n")
	if originalTrailingNewline {
		updated += "\n"
	}
	return updated, nil
}

func patchHunkCount(value string) int {
	if value == "" {
		return 1
	}
	count, _ := strconv.Atoi(value)
	return count
}
