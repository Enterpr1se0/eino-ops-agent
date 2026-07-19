//go:build windows

package sshx

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Microsoft/go-winio"
)

const windowsOpenSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

func openSSHAgent(ctx context.Context) (net.Conn, error) {
	pipe := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if !strings.HasPrefix(strings.ToLower(pipe), `\\.\pipe\`) {
		pipe = windowsOpenSSHAgentPipe
	}
	connection, err := winio.DialPipeContext(ctx, pipe)
	if err != nil {
		return nil, fmt.Errorf("connect Windows OpenSSH Agent %q: %w", pipe, err)
	}
	return connection, nil
}
