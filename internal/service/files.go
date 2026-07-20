package service

import (
	"context"
	"fmt"
	posixpath "path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/ids"
)

const (
	fileMetaMarker       = "__OPS_FILE_META__"
	fileContentMarker    = "__OPS_FILE_CONTENT__"
	fileBeforeMarker     = "__OPS_FILE_BEFORE__"
	fileBackupMarker     = "__OPS_FILE_BACKUP__"
	fileAfterMarker      = "__OPS_FILE_AFTER__"
	fileValidationMarker = "__OPS_FILE_VALIDATION_OK__"
)

func (s *Service) ReadFileAdvanced(ctx context.Context, hostID, path string, maxBytes int, offsetBytes int64, tailLines int, elevated bool, actor string) (domain.ExecResult, error) {
	if err := validateRemoteFilePath(path); err != nil {
		return domain.ExecResult{}, err
	}
	if offsetBytes < 0 || tailLines < 0 || (offsetBytes > 0 && tailLines > 0) {
		return domain.ExecResult{}, fmt.Errorf("invalid file range: offset_bytes and tail_lines are non-negative and mutually exclusive")
	}
	if tailLines > 5000 {
		tailLines = 5000
	}
	if maxBytes <= 0 || maxBytes > s.limits.ModelOutputBytes {
		maxBytes = s.limits.ModelOutputBytes
	}
	quoted := shellQuote(path)
	lines := []string{
		"set -e",
		"printf '" + fileMetaMarker + "\\n'",
		"stat -Lc '%s\\t%a\\t%U\\t%G\\t%Y' -- " + quoted,
		"sha256sum -- " + quoted,
		"printf '" + fileContentMarker + "\\n'",
	}
	switch {
	case tailLines > 0:
		lines = append(lines, "tail -n "+strconv.Itoa(tailLines)+" -- "+quoted+" | head -c "+strconv.Itoa(maxBytes))
	case offsetBytes > 0:
		lines = append(lines, "tail -c +"+strconv.FormatInt(offsetBytes+1, 10)+" -- "+quoted+" | head -c "+strconv.Itoa(maxBytes))
	default:
		lines = append(lines, "head -c "+strconv.Itoa(maxBytes)+" -- "+quoted)
	}
	result, err := s.Submit(ctx, domain.ExecRequest{
		HostID: hostID, Mode: domain.ExecScript, Script: strings.Join(lines, "\n"), Elevated: elevated,
		Reason: "read a bounded remote file with version metadata",
	}, actor)
	if result.Stdout != "" {
		metadata, content := parseFileReadOutput(path, result.Stdout)
		metadata.OffsetBytes = offsetBytes
		metadata.ReturnedBytes = len(content)
		metadata.Sensitive = strings.Contains(content, "[REDACTED]")
		result.File = &metadata
		result.Stdout = content
	}
	return result, err
}

func (s *Service) SearchFile(ctx context.Context, hostID, path, pattern string, contextLines, maxMatches int, elevated bool, actor string) (domain.ExecResult, error) {
	if err := validateRemoteFilePath(path); err != nil {
		return domain.ExecResult{}, err
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || len(pattern) > 512 || strings.ContainsAny(pattern, "\x00\r\n") {
		return domain.ExecResult{}, fmt.Errorf("invalid search pattern: use 1-512 characters on one line")
	}
	if contextLines < 0 {
		return domain.ExecResult{}, fmt.Errorf("invalid context_lines")
	}
	if contextLines > 10 {
		contextLines = 10
	}
	if maxMatches <= 0 || maxMatches > 200 {
		maxMatches = 100
	}
	script := "grep -n -F -C " + strconv.Itoa(contextLines) + " -- " + shellQuote(pattern) + " " + shellQuote(path) + " | head -n " + strconv.Itoa(maxMatches)
	return s.Submit(ctx, domain.ExecRequest{HostID: hostID, Mode: domain.ExecScript, Script: script, Elevated: elevated, Reason: "search bounded literal matches in a remote file"}, actor)
}

func (s *Service) ApplyRemoteConfig(ctx context.Context, hostID, path, content, patchContent, expectedSHA256, validatorID string, elevated bool, reason, rollback, actor string) (domain.ExecResult, error) {
	if err := validateRemoteFilePath(path); err != nil {
		return domain.ExecResult{}, err
	}
	if content != "" && patchContent != "" {
		return domain.ExecResult{}, fmt.Errorf("content and patch are mutually exclusive")
	}
	if len(content) > 1<<20 || len(patchContent) > 1<<20 {
		return domain.ExecResult{}, fmt.Errorf("configuration change exceeds 1 MiB")
	}
	if strings.TrimSpace(reason) == "" || strings.TrimSpace(rollback) == "" {
		return domain.ExecResult{}, fmt.Errorf("reason and rollback are required")
	}
	if expectedSHA256 != "" && expectedSHA256 != "absent" && !regexp.MustCompile(`^[a-fA-F0-9]{64}$`).MatchString(expectedSHA256) {
		return domain.ExecResult{}, fmt.Errorf("expected_sha256 must be a 64-character SHA256 or absent")
	}
	changeData := content
	if patchContent != "" {
		changeData = patchContent
	}
	if strings.Contains(changeData, "[REDACTED]") || s.redactor.Redact(changeData) != changeData {
		return domain.ExecResult{}, fmt.Errorf("configuration input contains a secret or redaction placeholder; use a change that does not expose or overwrite secret values")
	}
	validatorCommand, err := s.validatorCommandFor(validatorID, "remote", path, path)
	if err != nil {
		return domain.ExecResult{}, err
	}
	suffix := time.Now().UTC().Format("20060102T150405Z") + "-" + ids.New("file")
	directory := posixpath.Dir(path)
	base := posixpath.Base(path)
	backupPath := posixpath.Join(directory, ".opspilot-"+base+"-"+suffix+".bak")
	tempPath := posixpath.Join(directory, ".opspilot-"+base+"-"+suffix+".tmp")
	tempValidatorCommand, err := s.validatorCommandFor(validatorID, "remote", path, tempPath)
	if err != nil {
		return domain.ExecResult{}, err
	}
	script := buildConfigTransactionScript(path, tempPath, backupPath, content, patchContent, expectedSHA256, tempValidatorCommand, validatorCommand, elevated)
	result, submitErr := s.Submit(ctx, domain.ExecRequest{
		HostID: hostID, Mode: domain.ExecScript, Script: script, Elevated: elevated, Reason: reason,
		ExpectedChanges: "transactionally update configuration file " + path,
		Rollback:        rollback + "; protected backup: " + backupPath, RemotePath: path, ExpectedSHA256: expectedSHA256, Validator: validatorID,
	}, actor)
	metadata := parseConfigTransactionOutput(path, validatorID, result.Stdout)
	result.File = &metadata
	if result.ExitCode == 73 {
		return result, fmt.Errorf("conflict: remote file changed or its existence does not match expected_sha256")
	}
	if result.ExitCode == 74 {
		return result, fmt.Errorf("validation failed; the previous file was restored")
	}
	if submitErr == nil && result.Status == "completed" {
		operation := domain.FileOperation{
			ID: ids.New("fileop"), RunID: result.RunID, HostID: hostID, Path: path, BackupPath: metadata.BackupPath,
			BeforeSHA256: metadata.BeforeSHA256, AfterSHA256: metadata.SHA256, Validator: validatorID, Status: "completed", CreatedAt: time.Now().UTC(),
		}
		if err := s.store.CreateFileOperation(ctx, operation); err != nil {
			return result, fmt.Errorf("persist file operation: %w", err)
		}
		result.File.OperationID = operation.ID
		result.File.BackupPath = operation.BackupPath
		result.Message = "file operation " + operation.ID + " completed"
		result.NextAction = "verify the consuming service; use ssh_config_restore with operation_id " + operation.ID + " if rollback is required"
	}
	return result, submitErr
}

func (s *Service) ApplyRemoteConfigVersioned(ctx context.Context, hostID, path, content, patchContent, expectedSHA256, validatorID string, elevated bool, reason, rollback, actor string) (domain.ExecResult, error) {
	if strings.TrimSpace(expectedSHA256) == "" {
		return domain.ExecResult{}, fmt.Errorf("expected_sha256 is required; read the current file first or use absent for a new file")
	}
	return s.ApplyRemoteConfig(ctx, hostID, path, content, patchContent, expectedSHA256, validatorID, elevated, reason, rollback, actor)
}

func (s *Service) ApplyPatchChecked(ctx context.Context, hostID, cwd, patchContent, expectedSHA256, validatorID string, elevated bool, reason, rollback, actor string) (domain.ExecResult, error) {
	path, err := singlePatchTarget(cwd, patchContent)
	if err != nil {
		return domain.ExecResult{}, err
	}
	return s.ApplyRemoteConfig(ctx, hostID, path, "", patchContent, expectedSHA256, validatorID, elevated, reason, rollback, actor)
}

func (s *Service) RestoreRemoteConfig(ctx context.Context, operationID string, elevated bool, reason, actor string) (domain.ExecResult, error) {
	operation, err := s.store.GetFileOperation(ctx, strings.TrimSpace(operationID))
	if err != nil {
		return domain.ExecResult{}, err
	}
	if operation.BackupPath == "" {
		return domain.ExecResult{}, fmt.Errorf("file operation has no restorable backup")
	}
	validatorCommand, err := s.validatorCommandFor(operation.Validator, "remote", operation.Path, operation.Path)
	if err != nil {
		return domain.ExecResult{}, err
	}
	tempPath := operation.Path + ".opspilot-restore-" + ids.New("file") + ".tmp"
	preRestorePath := operation.Path + ".opspilot-restore-" + ids.New("file") + ".bak"
	tempValidatorCommand, err := s.validatorCommandFor(operation.Validator, "remote", operation.Path, tempPath)
	if err != nil {
		return domain.ExecResult{}, err
	}
	lines := []string{
		"set -eu",
		"trap " + shellQuote("test ! -e "+shellQuote(tempPath)+" || unlink -- "+shellQuote(tempPath)+"; test ! -e "+shellQuote(preRestorePath)+" || unlink -- "+shellQuote(preRestorePath)) + " EXIT",
		"test -f " + shellQuote(operation.BackupPath),
		"printf '%s  %s\\n' " + shellQuote(operation.AfterSHA256) + " " + shellQuote(operation.Path) + " | sha256sum -c - || exit 73",
		"cp -p -- " + shellQuote(operation.Path) + " " + shellQuote(preRestorePath),
		"chmod 0600 -- " + shellQuote(preRestorePath),
		"cmp -s -- " + shellQuote(operation.Path) + " " + shellQuote(preRestorePath) + " || exit 73",
		"sync -f -- " + shellQuote(preRestorePath),
		"cp -p -- " + shellQuote(operation.BackupPath) + " " + shellQuote(tempPath),
		"sync -f -- " + shellQuote(tempPath),
	}
	if validatorCommand != "" {
		lines = append(lines, "if ! "+tempValidatorCommand+"; then unlink -- "+shellQuote(tempPath)+"; exit 74; fi")
	}
	lines = append(lines,
		"cmp -s -- "+shellQuote(operation.Path)+" "+shellQuote(preRestorePath)+" || exit 73",
		"mv -f -- "+shellQuote(tempPath)+" "+shellQuote(operation.Path),
		"sync -f -- "+shellQuote(operation.Path),
		"sync -f -- "+shellQuote(posixpath.Dir(operation.Path)),
	)
	if validatorCommand != "" {
		lines = append(lines,
			"if ! "+validatorCommand+"; then",
			"  cp -p -- "+shellQuote(preRestorePath)+" "+shellQuote(tempPath),
			"  sync -f -- "+shellQuote(tempPath),
			"  mv -f -- "+shellQuote(tempPath)+" "+shellQuote(operation.Path),
			"  sync -f -- "+shellQuote(operation.Path),
			"  sync -f -- "+shellQuote(posixpath.Dir(operation.Path)),
			"  unlink -- "+shellQuote(preRestorePath),
			"  exit 74",
			"fi",
		)
	}
	lines = append(lines, "unlink -- "+shellQuote(preRestorePath), "trap - EXIT", "printf '"+fileAfterMarker+"\\n'", "sha256sum -- "+shellQuote(operation.Path))
	result, submitErr := s.Submit(ctx, domain.ExecRequest{
		HostID: operation.HostID, Mode: domain.ExecScript, Script: strings.Join(lines, "\n"), Elevated: elevated,
		Reason: reason, ExpectedChanges: "restore configuration from audited operation " + operation.ID,
		Rollback: "reapply the reviewed change from run " + operation.RunID, RemotePath: operation.Path, ExpectedSHA256: operation.AfterSHA256, Validator: operation.Validator,
	}, actor)
	metadata := parseConfigTransactionOutput(operation.Path, operation.Validator, result.Stdout)
	metadata.BeforeSHA256 = operation.AfterSHA256
	metadata.BackupPath = operation.BackupPath
	result.File = &metadata
	if result.ExitCode == 73 {
		return result, fmt.Errorf("conflict: current file no longer matches the operation being restored")
	}
	if result.ExitCode == 74 {
		return result, fmt.Errorf("validation failed while restoring the backup")
	}
	return result, submitErr
}

func buildConfigTransactionScript(path, tempPath, backupPath, content, patchContent, expectedSHA256, tempValidatorCommand, validatorCommand string, elevated bool) string {
	pathQ, tempQ, backupQ := shellQuote(path), shellQuote(tempPath), shellQuote(backupPath)
	lines := []string{"set -eu", "if test -e " + pathQ + "; then", "  ops_had_original=1", "  printf '" + fileBeforeMarker + "\\n'", "  sha256sum -- " + pathQ}
	if expectedSHA256 == "absent" {
		lines = append(lines, "  exit 73")
	} else if expectedSHA256 != "" {
		lines = append(lines, "  printf '%s  %s\\n' "+shellQuote(strings.ToLower(expectedSHA256))+" "+pathQ+" | sha256sum -c - || exit 73")
	}
	lines = append(lines, "  cp -p -- "+pathQ+" "+backupQ, "  chmod 0600 -- "+backupQ, "  cmp -s -- "+pathQ+" "+backupQ+" || exit 73", "  sync -f -- "+backupQ, "  printf '"+fileBackupMarker+"\\n%s\\n' "+backupQ, "else", "  ops_had_original=0", "  printf '"+fileBeforeMarker+"\\nabsent\\n'")
	if expectedSHA256 != "" && expectedSHA256 != "absent" {
		lines = append(lines, "  exit 73")
	}
	lines = append(lines, "fi", "test ! -e "+tempQ+" || exit 73")
	marker := configHeredocMarker(content + patchContent)
	lines = append(lines, "trap "+shellQuote("test ! -e "+tempQ+" || unlink -- "+tempQ)+" EXIT")
	if patchContent != "" {
		lines = append(lines, "test -e "+pathQ+" || exit 73", "cp -p -- "+pathQ+" "+tempQ, "patch --batch --forward "+tempQ+" <<'"+marker+"'", patchContent, marker)
	} else {
		lines = append(lines, "umask 077", "cat > "+tempQ+" <<'"+marker+"'", content, marker, "if test -e "+pathQ+"; then", "  chmod --reference="+pathQ+" -- "+tempQ)
		if elevated {
			lines = append(lines, "  chown --reference="+pathQ+" -- "+tempQ)
		}
		lines = append(lines, "else", "  chmod 0600 -- "+tempQ, "fi")
	}
	lines = append(lines, "sync -f -- "+tempQ)
	if validatorCommand != "" {
		lines = append(lines, "if ! "+tempValidatorCommand+"; then", "  unlink -- "+tempQ, "  exit 74", "fi")
	}
	lines = append(lines,
		"if test \"$ops_had_original\" = 1; then cmp -s -- "+pathQ+" "+backupQ+" || exit 73; else test ! -e "+pathQ+" || exit 73; fi",
		"mv -f -- "+tempQ+" "+pathQ,
		"trap - EXIT",
		"sync -f -- "+pathQ,
		"sync -f -- "+shellQuote(posixpath.Dir(path)),
	)
	if validatorCommand != "" {
		lines = append(lines,
			"if ! "+validatorCommand+"; then",
			"  if test -e "+backupQ+"; then",
			"    cp -p -- "+backupQ+" "+tempQ,
			"    sync -f -- "+tempQ,
			"    mv -f -- "+tempQ+" "+pathQ,
			"    sync -f -- "+pathQ,
			"  else",
			"    unlink -- "+pathQ,
			"  fi",
			"  sync -f -- "+shellQuote(posixpath.Dir(path)),
			"  exit 74",
			"fi",
			"printf '"+fileValidationMarker+"\\n'",
		)
	}
	lines = append(lines, "printf '"+fileAfterMarker+"\\n'", "sha256sum -- "+pathQ)
	return strings.Join(lines, "\n")
}

func configHeredocMarker(content string) string {
	for {
		marker := "__OPS_CONFIG_" + strings.TrimPrefix(ids.New("cfg"), "cfg_") + "__"
		conflict := false
		for _, line := range strings.Split(content, "\n") {
			if line == marker {
				conflict = true
				break
			}
		}
		if !conflict {
			return marker
		}
	}
}

func (s *Service) validatorCommandFor(id, scope, allowedPath, executionPath string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", nil
	}
	validator, ok := s.validators[id]
	if !ok || validator.Scope != scope {
		return "", fmt.Errorf("invalid validator %q for %s operations", id, scope)
	}
	if !validatorAllowsPath(validator, allowedPath) {
		return "", fmt.Errorf("validator %q is not allowed for path %s", id, allowedPath)
	}
	parts := []string{"timeout", "--signal=KILL", strconv.Itoa(validator.TimeoutSeconds) + "s", shellQuote(validator.Program)}
	for _, argument := range validator.Args {
		parts = append(parts, shellQuote(strings.ReplaceAll(argument, "{{path}}", executionPath)))
	}
	return strings.Join(parts, " "), nil
}

func validatorAllowsPath(validator config.Validator, path string) bool {
	if len(validator.PathPatterns) == 0 {
		return false
	}
	clean := posixpath.Clean(path)
	for _, pattern := range validator.PathPatterns {
		pattern = posixpath.Clean(pattern)
		if strings.HasSuffix(pattern, "/**") {
			root := strings.TrimSuffix(pattern, "/**")
			if clean == root || strings.HasPrefix(clean, root+"/") {
				return true
			}
		} else if matched, _ := posixpath.Match(pattern, clean); matched {
			return true
		}
	}
	return false
}

func validateRemoteFilePath(path string) error {
	if !posixpath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") || posixpath.Clean(path) != path {
		return fmt.Errorf("remote file path must be a clean absolute path")
	}
	return nil
}

func parseFileReadOutput(path, output string) (domain.FileMetadata, string) {
	metadata := domain.FileMetadata{Path: path}
	metaIndex := strings.Index(output, fileMetaMarker+"\n")
	contentIndex := strings.Index(output, fileContentMarker+"\n")
	if metaIndex < 0 || contentIndex < 0 || contentIndex <= metaIndex {
		return metadata, output
	}
	metaLines := strings.Split(strings.TrimSpace(output[metaIndex+len(fileMetaMarker)+1:contentIndex]), "\n")
	if len(metaLines) > 0 {
		fields := strings.Split(metaLines[0], "\t")
		if len(fields) >= 5 {
			metadata.Size, _ = strconv.ParseInt(fields[0], 10, 64)
			metadata.Mode, metadata.Owner, metadata.Group = fields[1], fields[2], fields[3]
			metadata.ModifiedUnix, _ = strconv.ParseInt(fields[4], 10, 64)
		}
	}
	if len(metaLines) > 1 {
		fields := strings.Fields(metaLines[1])
		if len(fields) > 0 {
			metadata.SHA256 = fields[0]
		}
	}
	return metadata, output[contentIndex+len(fileContentMarker)+1:]
}

func parseConfigTransactionOutput(path, validatorID, output string) domain.FileMetadata {
	metadata := domain.FileMetadata{Path: path, Validator: validatorID, ValidationOK: validatorID == "" || strings.Contains(output, fileValidationMarker)}
	lines := strings.Split(output, "\n")
	for index, line := range lines {
		if index+1 >= len(lines) {
			continue
		}
		value := strings.TrimSpace(lines[index+1])
		switch strings.TrimSpace(line) {
		case fileBeforeMarker:
			if value != "absent" {
				fields := strings.Fields(value)
				if len(fields) > 0 {
					metadata.BeforeSHA256 = fields[0]
				}
			}
		case fileBackupMarker:
			metadata.BackupPath = value
		case fileAfterMarker:
			fields := strings.Fields(value)
			if len(fields) > 0 {
				metadata.SHA256 = fields[0]
			}
		}
	}
	return metadata
}

func singlePatchTarget(cwd, patchContent string) (string, error) {
	if !posixpath.IsAbs(cwd) || posixpath.Clean(cwd) != cwd {
		return "", fmt.Errorf("remote working directory must be a clean absolute path")
	}
	targets := make(map[string]struct{})
	for _, line := range strings.Split(patchContent, "\n") {
		if !strings.HasPrefix(line, "+++ ") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "+++ "))
		if len(fields) == 0 {
			return "", fmt.Errorf("patch target is missing")
		}
		value := fields[0]
		if value == "/dev/null" {
			continue
		}
		value = strings.TrimPrefix(value, "b/")
		value = strings.TrimPrefix(value, "a/")
		if posixpath.IsAbs(value) || value == ".." || strings.HasPrefix(value, "../") {
			return "", fmt.Errorf("patch target escapes the working directory")
		}
		targets[value] = struct{}{}
	}
	if len(targets) != 1 {
		return "", fmt.Errorf("remote patch must modify exactly one file; apply multi-file changes as independently approved steps")
	}
	var relative string
	for value := range targets {
		relative = value
	}
	target := posixpath.Clean(posixpath.Join(cwd, relative))
	if target != cwd && !strings.HasPrefix(target, cwd+"/") {
		return "", fmt.Errorf("patch target escapes the working directory")
	}
	return target, nil
}
