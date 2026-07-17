package sshx

import (
	"io"
	"os/exec"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
)

func TestBuildRemoteProgramQuotesArguments(t *testing.T) {
	command, stdin, err := buildRemoteCommand(domain.ExecRequest{
		Mode: domain.ExecProgram, Program: "printf", Args: []string{"%s", "hello; rm -rf /"}, Cwd: "/srv/app",
		Env: map[string]string{"MODE": "safe value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stdin != nil {
		t.Fatal("program mode unexpectedly has stdin")
	}
	wantParts := []string{"cd -- '/srv/app' &&", "MODE='safe value'", "'hello; rm -rf /'"}
	for _, part := range wantParts {
		if !strings.Contains(command, part) {
			t.Fatalf("command %q does not contain %q", command, part)
		}
	}
}

func TestManagedSudoPasswordUsesStdin(t *testing.T) {
	command, stdin, err := applyElevation(domain.Host{SudoMode: "password", SudoPassword: "sudo-secret"}, domain.ExecRequest{Elevated: true}, "bash -se", strings.NewReader("echo ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if command != "sudo -S -p '' -- bash -c 'bash -se'" || strings.Contains(command, "sudo-secret") {
		t.Fatalf("unexpected elevated command %q", command)
	}
	data, _ := io.ReadAll(stdin)
	if string(data) != "sudo-secret\necho ok\n" {
		t.Fatalf("unexpected managed sudo stdin %q", data)
	}
}

func TestPasswordAuthenticationUsesAskPassWithoutSecretInProcessMetadata(t *testing.T) {
	host := domain.Host{AuthType: "password", Password: "ssh secret with spaces"}
	cmd := exec.Command("/bin/sh", "-c", `"$SSH_ASKPASS"`)
	cleanup, err := preparePasswordAuthentication(cmd, host)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, value := range append(cmd.Args, cmd.Env...) {
		if strings.Contains(value, host.Password) {
			t.Fatalf("SSH password leaked into argv or environment: %q", value)
		}
	}
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != host.Password {
		t.Fatalf("askpass returned %q", output)
	}
}

func TestPasswordSSHArgsDisableBatchModeWithoutLeakingPassword(t *testing.T) {
	transport := NewOpenSSHTransport(config.OpenSSH{}, config.Limits{}, "")
	host := domain.Host{Address: "192.0.2.1", Port: 22, User: "ops", AuthType: "password", Password: "secret"}
	args, err := transport.sshArgs(host, "id")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "BatchMode=no") || !strings.Contains(joined, "NumberOfPasswordPrompts=1") {
		t.Fatalf("password authentication options missing: %s", joined)
	}
	if strings.Contains(joined, host.Password) {
		t.Fatal("SSH password leaked into arguments")
	}
}

func TestBuildRemoteScriptUsesStdin(t *testing.T) {
	command, stdin, err := buildRemoteCommand(domain.ExecRequest{Mode: domain.ExecScript, Script: "uname -a"})
	if err != nil {
		t.Fatal(err)
	}
	if command != "bash -se" {
		t.Fatalf("unexpected command %q", command)
	}
	data, _ := io.ReadAll(stdin)
	if string(data) != "uname -a" {
		t.Fatalf("unexpected stdin %q", data)
	}
}

func TestProbeScriptFallsBackWhenCommonUtilitiesAreMissing(t *testing.T) {
	cmd := exec.Command("/bin/bash", "-se")
	cmd.Env = []string{"PATH=/opspilot-no-such-path"}
	cmd.Stdin = strings.NewReader(probeScript)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	info, err := parseProbeOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname == "" || info.Kernel == "" || info.Architecture == "" || info.User == "" || info.Uptime == "" {
		t.Fatalf("probe fallback returned incomplete info: %#v", info)
	}
}

func TestValidateHostRejectsOptionInjection(t *testing.T) {
	err := validateHost(domain.Host{Address: "-oProxyCommand=evil", User: "root", Port: 22})
	if err == nil {
		t.Fatal("expected host validation error")
	}
}

func TestSFTPQuote(t *testing.T) {
	quoted := sftpQuote(`/tmp/a "quoted" file`)
	if quoted != `"/tmp/a \"quoted\" file"` {
		t.Fatalf("unexpected SFTP quoting: %q", quoted)
	}
}
