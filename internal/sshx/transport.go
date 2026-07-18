package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
)

type RawResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	Duration  time.Duration
}

type HostInfo struct {
	Hostname     string `json:"hostname"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	User         string `json:"user"`
	Uptime       string `json:"uptime"`
}

type HostKey struct {
	Lines       string `json:"lines"`
	Fingerprint string `json:"fingerprint"`
}

type Transport interface {
	Exec(context.Context, domain.Host, domain.ExecRequest) (RawResult, error)
	Probe(context.Context, domain.Host) (HostInfo, error)
	ScanHostKey(context.Context, domain.Host) (HostKey, error)
	TrustHostKey(context.Context, domain.Host, string) (HostKey, error)
}

type StreamingTransport interface {
	ExecStream(context.Context, domain.Host, domain.ExecRequest, func(stream string, data []byte)) (RawResult, error)
}

type OpenSSHTransport struct {
	config config.OpenSSH
	limits config.Limits
}

func NewOpenSSHTransport(cfg config.OpenSSH, limits config.Limits) *OpenSSHTransport {
	return &OpenSSHTransport{config: cfg, limits: limits}
}

func (t *OpenSSHTransport) Exec(ctx context.Context, host domain.Host, req domain.ExecRequest) (RawResult, error) {
	return t.execWithCallback(ctx, host, req, nil)
}

func (t *OpenSSHTransport) ExecStream(ctx context.Context, host domain.Host, req domain.ExecRequest, callback func(string, []byte)) (RawResult, error) {
	return t.execWithCallback(ctx, host, req, callback)
}

func (t *OpenSSHTransport) execWithCallback(ctx context.Context, host domain.Host, req domain.ExecRequest, callback func(string, []byte)) (RawResult, error) {
	if err := validateHost(host); err != nil {
		return RawResult{}, err
	}
	if req.Mode == domain.ExecWorkspaceUpload {
		return t.transfer(ctx, host, req)
	}
	command, stdin, err := buildRemoteCommand(req)
	if err != nil {
		return RawResult{}, err
	}
	command, stdin, err = applyElevation(host, req, command, stdin)
	if err != nil {
		return RawResult{}, err
	}
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = t.limits.SyncTimeoutSeconds
	}
	if timeout > t.limits.MaxTimeoutSeconds {
		timeout = t.limits.MaxTimeoutSeconds
	}
	if timeout <= 0 {
		timeout = 60
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	args, err := t.sshArgs(host, command)
	if err != nil {
		return RawResult{}, err
	}
	cmd := exec.CommandContext(execCtx, t.config.SSHPath, args...)
	cmd.Stdin = stdin
	cleanupAuth, err := preparePasswordAuthentication(cmd, host)
	if err != nil {
		return RawResult{}, err
	}
	defer cleanupAuth()
	maxBytes := t.limits.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	stdout := newLimitBuffer(maxBytes)
	stderr := newLimitBuffer(maxBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if callback != nil {
		cmd.Stdout = io.MultiWriter(stdout, callbackWriter{stream: "stdout", callback: callback})
		cmd.Stderr = io.MultiWriter(stderr, callbackWriter{stream: "stderr", callback: callback})
	}
	started := time.Now()
	err = cmd.Run()
	result := RawResult{
		ExitCode:  exitCode(err),
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Duration:  time.Since(started),
	}
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("remote command timed out after %s", time.Duration(timeout)*time.Second)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return result, fmt.Errorf("start OpenSSH: %w", err)
		}
	}
	return result, nil
}

func (t *OpenSSHTransport) transfer(ctx context.Context, host domain.Host, req domain.ExecRequest) (RawResult, error) {
	if !filepath.IsAbs(req.RemotePath) || strings.ContainsAny(req.RemotePath, "\r\n\x00") {
		return RawResult{}, fmt.Errorf("remote transfer path must be absolute and contain no control characters")
	}
	localPath := req.LocalPath
	if !filepath.IsAbs(localPath) || strings.ContainsAny(localPath, "\r\n\x00") {
		return RawResult{}, fmt.Errorf("workspace upload source was not prepared by the control plane")
	}
	info, err := os.Stat(localPath)
	if err != nil || !info.Mode().IsRegular() {
		return RawResult{}, fmt.Errorf("transfer source is missing or not a regular file")
	}
	batch := "put " + sftpQuote(localPath) + " " + sftpQuote(req.RemotePath) + "\n"
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = t.limits.SyncTimeoutSeconds
	}
	if timeout > t.limits.MaxTimeoutSeconds {
		timeout = t.limits.MaxTimeoutSeconds
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	args, err := t.sftpArgs(host)
	if err != nil {
		return RawResult{}, err
	}
	path := t.config.SFTPPath
	if path == "" {
		path = "sftp"
	}
	cmd := exec.CommandContext(execCtx, path, args...)
	cmd.Stdin = strings.NewReader(batch)
	cleanupAuth, err := preparePasswordAuthentication(cmd, host)
	if err != nil {
		return RawResult{}, err
	}
	defer cleanupAuth()
	maxBytes := t.limits.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	stdout := newLimitBuffer(maxBytes)
	stderr := newLimitBuffer(maxBytes)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started := time.Now()
	err = cmd.Run()
	result := RawResult{ExitCode: exitCode(err), Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Truncated: stdout.Truncated() || stderr.Truncated(), Duration: time.Since(started)}
	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		return result, fmt.Errorf("SFTP transfer timed out")
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return result, fmt.Errorf("start SFTP: %w", err)
		}
	}
	return result, nil
}

func (t *OpenSSHTransport) Probe(ctx context.Context, host domain.Host) (HostInfo, error) {
	req := domain.ExecRequest{
		Mode:           domain.ExecScript,
		Script:         probeScript,
		TimeoutSeconds: 15,
	}
	result, err := t.Exec(ctx, host, req)
	if err != nil {
		return HostInfo{}, err
	}
	if result.ExitCode != 0 {
		return HostInfo{}, fmt.Errorf("probe failed: %s", strings.TrimSpace(string(result.Stderr)))
	}
	return parseProbeOutput(result.Stdout)
}

const probeScript = `probe_hostname=""
if command -v hostname >/dev/null 2>&1; then probe_hostname=$(hostname 2>/dev/null) || probe_hostname=""; fi
if [ -z "$probe_hostname" ]; then IFS= read -r probe_hostname </proc/sys/kernel/hostname || probe_hostname="unknown"; fi
printf '%s\n' "${probe_hostname:-unknown}"

probe_kernel=""
if command -v uname >/dev/null 2>&1; then probe_kernel=$(uname -sr 2>/dev/null) || probe_kernel=""; fi
if [ -z "$probe_kernel" ]; then
  probe_ostype=""; probe_release=""
  IFS= read -r probe_ostype </proc/sys/kernel/ostype || probe_ostype="Linux"
  IFS= read -r probe_release </proc/sys/kernel/osrelease || probe_release="unknown"
  probe_kernel="$probe_ostype $probe_release"
fi
printf '%s\n' "$probe_kernel"

probe_arch=""
if command -v uname >/dev/null 2>&1; then probe_arch=$(uname -m 2>/dev/null) || probe_arch=""; fi
printf '%s\n' "${probe_arch:-${HOSTTYPE:-unknown}}"

probe_user=""
if command -v whoami >/dev/null 2>&1; then probe_user=$(whoami 2>/dev/null) || probe_user=""; fi
if [ -z "$probe_user" ] && command -v id >/dev/null 2>&1; then probe_user=$(id -un 2>/dev/null) || probe_user=""; fi
printf '%s\n' "${probe_user:-${USER:-${LOGNAME:-unknown}}}"

probe_uptime=""
if command -v uptime >/dev/null 2>&1; then probe_uptime=$(uptime -p 2>/dev/null) || probe_uptime=$(uptime 2>/dev/null) || probe_uptime=""; fi
if [ -z "$probe_uptime" ]; then
  probe_seconds=""
  IFS=' ' read -r probe_seconds _ </proc/uptime || probe_seconds="unknown"
  probe_uptime="up ${probe_seconds:-unknown} seconds"
fi
printf '%s\n' "$probe_uptime"`

func parseProbeOutput(output []byte) (HostInfo, error) {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) < 5 {
		return HostInfo{}, fmt.Errorf("unexpected probe output")
	}
	return HostInfo{Hostname: lines[0], Kernel: lines[1], Architecture: lines[2], User: lines[3], Uptime: strings.Join(lines[4:], "\n")}, nil
}

func (t *OpenSSHTransport) ScanHostKey(ctx context.Context, host domain.Host) (HostKey, error) {
	if err := validateHost(host); err != nil {
		return HostKey{}, err
	}
	if host.ConfigAlias != "" && host.Address == "" {
		return HostKey{}, fmt.Errorf("address is required to scan a host key")
	}
	args := []string{"-T", "5", "-p", strconv.Itoa(host.Port), host.Address}
	cmd := exec.CommandContext(ctx, t.config.SSHKeyscanPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		return HostKey{}, fmt.Errorf("ssh-keyscan: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return HostKey{}, fmt.Errorf("ssh-keyscan returned no host keys")
	}
	fingerprint, err := t.fingerprint(ctx, data)
	if err != nil {
		return HostKey{}, err
	}
	return HostKey{Lines: string(data), Fingerprint: fingerprint}, nil
}

func (t *OpenSSHTransport) TrustHostKey(ctx context.Context, host domain.Host, expectedFingerprint string) (HostKey, error) {
	key, err := t.ScanHostKey(ctx, host)
	if err != nil {
		return HostKey{}, err
	}
	if expectedFingerprint == "" || !strings.Contains(key.Fingerprint, expectedFingerprint) {
		return HostKey{}, fmt.Errorf("host key fingerprint mismatch; scanned: %s", key.Fingerprint)
	}
	path := host.KnownHostsFile
	if path == "" {
		path = t.config.DefaultKnownHosts
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return HostKey{}, err
	}
	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return HostKey{}, err
	}
	if bytes.Contains(existing, bytes.TrimSpace([]byte(key.Lines))) {
		return key, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return HostKey{}, err
	}
	defer file.Close()
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		if _, err := file.WriteString("\n"); err != nil {
			return HostKey{}, err
		}
	}
	if _, err := file.WriteString(strings.TrimSpace(key.Lines) + "\n"); err != nil {
		return HostKey{}, err
	}
	return key, nil
}

func (t *OpenSSHTransport) fingerprint(ctx context.Context, key []byte) (string, error) {
	cmd := exec.CommandContext(ctx, t.config.SSHKeygenPath, "-lf", "-")
	cmd.Stdin = bytes.NewReader(key)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ssh-keygen fingerprint: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func (t *OpenSSHTransport) sshArgs(host domain.Host, remoteCommand string) ([]string, error) {
	knownHosts := host.KnownHostsFile
	if knownHosts == "" {
		knownHosts = t.config.DefaultKnownHosts
	}
	batchMode := "yes"
	if host.AuthType == "password" {
		batchMode = "no"
	}
	args := []string{
		"-o", "BatchMode=" + batchMode,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
	}
	if host.AuthType == "password" {
		args = append(args,
			"-o", "NumberOfPasswordPrompts=1",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "PubkeyAuthentication=no",
		)
	}
	if knownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+knownHosts)
	}
	if host.AuthType == "key" && host.IdentityFile != "" {
		args = append(args, "-i", host.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if host.ProxyJump != "" {
		args = append(args, "-J", host.ProxyJump)
	}
	var target string
	if host.ConfigAlias != "" {
		target = host.ConfigAlias
	} else {
		args = append(args, "-p", strconv.Itoa(host.Port))
		target = host.User + "@" + host.Address
	}
	args = append(args, target, remoteCommand)
	return args, nil
}

func (t *OpenSSHTransport) sftpArgs(host domain.Host) ([]string, error) {
	knownHosts := host.KnownHostsFile
	if knownHosts == "" {
		knownHosts = t.config.DefaultKnownHosts
	}
	batchMode := "yes"
	if host.AuthType == "password" {
		batchMode = "no"
	}
	// sftp's -b option injects "-obatchmode yes" into the underlying ssh
	// command. OpenSSH keeps the first value for each option, so our explicit
	// password-host override must appear before -b or SSH_ASKPASS is never used.
	args := []string{"-o", "BatchMode=" + batchMode, "-b", "-", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"}
	if host.AuthType == "password" {
		args = append(args,
			"-o", "NumberOfPasswordPrompts=1",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "PubkeyAuthentication=no",
		)
	}
	if knownHosts != "" {
		args = append(args, "-o", "UserKnownHostsFile="+knownHosts)
	}
	if host.AuthType == "key" && host.IdentityFile != "" {
		args = append(args, "-i", host.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if host.ProxyJump != "" {
		args = append(args, "-J", host.ProxyJump)
	}
	var target string
	if host.ConfigAlias != "" {
		target = host.ConfigAlias
	} else {
		args = append(args, "-P", strconv.Itoa(host.Port))
		target = host.User + "@" + host.Address
	}
	return append(args, target), nil
}

func buildRemoteCommand(req domain.ExecRequest) (string, io.Reader, error) {
	if req.Mode == "" {
		if req.Script != "" {
			req.Mode = domain.ExecScript
		} else {
			req.Mode = domain.ExecProgram
		}
	}
	prefix, err := remotePrefix(req.Cwd, req.Env)
	if err != nil {
		return "", nil, err
	}
	switch req.Mode {
	case domain.ExecProgram:
		if !regexp.MustCompile(`^[A-Za-z0-9_./+:-]+$`).MatchString(req.Program) {
			return "", nil, fmt.Errorf("program contains unsupported characters")
		}
		parts := []string{shellQuote(req.Program)}
		for _, arg := range req.Args {
			parts = append(parts, shellQuote(arg))
		}
		return prefix + strings.Join(parts, " "), nil, nil
	case domain.ExecScript:
		if strings.TrimSpace(req.Script) == "" {
			return "", nil, fmt.Errorf("script is empty")
		}
		return prefix + "bash -se", strings.NewReader(req.Script), nil
	default:
		return "", nil, fmt.Errorf("unsupported execution mode %q", req.Mode)
	}
}

func applyElevation(host domain.Host, req domain.ExecRequest, command string, stdin io.Reader) (string, io.Reader, error) {
	if !req.Elevated {
		return command, stdin, nil
	}
	wrapped := "bash -c " + shellQuote(command)
	switch host.SudoMode {
	case "nopasswd":
		return "sudo -n -- " + wrapped, stdin, nil
	case "password":
		if host.SudoPassword == "" {
			return "", nil, fmt.Errorf("sudo password is unavailable")
		}
		if strings.ContainsAny(host.SudoPassword, "\x00\r\n") {
			return "", nil, fmt.Errorf("sudo password contains unsupported control characters")
		}
		if stdin == nil {
			stdin = strings.NewReader("")
		}
		return "sudo -S -p '' -- " + wrapped, io.MultiReader(strings.NewReader(host.SudoPassword+"\n"), stdin), nil
	default:
		return "", nil, fmt.Errorf("managed sudo is disabled for this host")
	}
}

// preparePasswordAuthentication gives OpenSSH a one-shot SSH_ASKPASS channel.
// The password stays out of argv, process environment, logs, and regular files:
// it is buffered only in a mode-0600 FIFO inside a mode-0700 temporary directory.
func preparePasswordAuthentication(cmd *exec.Cmd, host domain.Host) (func(), error) {
	if host.AuthType != "password" {
		return func() {}, nil
	}
	if host.Password == "" {
		return nil, fmt.Errorf("SSH password is unavailable")
	}
	if strings.ContainsAny(host.Password, "\x00\r\n") {
		return nil, fmt.Errorf("SSH password contains unsupported control characters")
	}
	tempDir, err := os.MkdirTemp("", "opspilot-askpass-")
	if err != nil {
		return nil, fmt.Errorf("create SSH askpass directory: %w", err)
	}
	cleanupDir := func() { _ = os.RemoveAll(tempDir) }
	if err := os.Chmod(tempDir, 0o700); err != nil {
		cleanupDir()
		return nil, err
	}
	fifoPath := filepath.Join(tempDir, "secret.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		cleanupDir()
		return nil, fmt.Errorf("create SSH askpass FIFO: %w", err)
	}
	helperPath := filepath.Join(tempDir, "askpass.sh")
	const helper = "#!/bin/sh\nexec dd if=\"$OPSPILOT_ASKPASS_FIFO\" bs=1 count=\"$OPSPILOT_ASKPASS_LENGTH\" 2>/dev/null\n"
	if err := os.WriteFile(helperPath, []byte(helper), 0o700); err != nil {
		cleanupDir()
		return nil, fmt.Errorf("create SSH askpass helper: %w", err)
	}
	fifo, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		cleanupDir()
		return nil, fmt.Errorf("open SSH askpass FIFO: %w", err)
	}
	// OpenSSH may fall back from password to keyboard-interactive. Buffer two
	// one-shot responses while NumberOfPasswordPrompts remains one per method.
	payload := bytes.Repeat([]byte(host.Password), 2)
	written, err := fifo.Write(payload)
	if err != nil || written != len(payload) {
		_ = fifo.Close()
		cleanupDir()
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, fmt.Errorf("prepare SSH askpass secret: %w", err)
	}
	cmd.Env = append(os.Environ(),
		"DISPLAY=opspilot:0",
		"SSH_ASKPASS_REQUIRE=force",
		"SSH_ASKPASS="+helperPath,
		"OPSPILOT_ASKPASS_FIFO="+fifoPath,
		"OPSPILOT_ASKPASS_LENGTH="+strconv.Itoa(len(host.Password)),
	)
	return func() {
		_ = fifo.Close()
		cleanupDir()
	}, nil
}

func remotePrefix(cwd string, env map[string]string) (string, error) {
	var parts []string
	if cwd != "" {
		if !filepath.IsAbs(cwd) {
			return "", fmt.Errorf("cwd must be an absolute path")
		}
		parts = append(parts, "cd -- "+shellQuote(cwd)+" &&")
	}
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for key := range env {
			if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) {
				return "", fmt.Errorf("invalid environment variable name %q", key)
			}
			keys = append(keys, key)
		}
		sortStrings(keys)
		values := make([]string, 0, len(keys)+1)
		values = append(values, "env")
		for _, key := range keys {
			values = append(values, key+"="+shellQuote(env[key]))
		}
		parts = append(parts, strings.Join(values, " "))
	}
	if len(parts) == 0 {
		return "", nil
	}
	return strings.Join(parts, " ") + " ", nil
}

func validateHost(host domain.Host) error {
	if host.Port <= 0 || host.Port > 65535 {
		return fmt.Errorf("invalid SSH port")
	}
	safeTarget := regexp.MustCompile(`^[A-Za-z0-9_.:@%+\[\]-]+$`)
	if host.ConfigAlias != "" {
		if !safeTarget.MatchString(host.ConfigAlias) || strings.HasPrefix(host.ConfigAlias, "-") {
			return fmt.Errorf("invalid SSH config alias")
		}
		return nil
	}
	if host.Address == "" || !safeTarget.MatchString(host.Address) || strings.HasPrefix(host.Address, "-") {
		return fmt.Errorf("invalid SSH address")
	}
	if host.User == "" || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(host.User) {
		return fmt.Errorf("invalid SSH user")
	}
	if host.ProxyJump != "" && (!safeTarget.MatchString(host.ProxyJump) || strings.HasPrefix(host.ProxyJump, "-")) {
		return fmt.Errorf("invalid ProxyJump")
	}
	return nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func sftpQuote(value string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

type limitBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

type callbackWriter struct {
	stream   string
	callback func(string, []byte)
}

func (w callbackWriter) Write(data []byte) (int, error) {
	w.callback(w.stream, bytes.Clone(data))
	return len(data), nil
}

func newLimitBuffer(limit int) *limitBuffer { return &limitBuffer{limit: limit} }

func (b *limitBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(data)
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if len(data) > remaining {
		_, _ = b.buf.Write(data[:remaining])
		b.truncated = true
		return original, nil
	}
	_, _ = b.buf.Write(data)
	return original, nil
}

func (b *limitBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

func (b *limitBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
