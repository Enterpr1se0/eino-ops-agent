//go:build !windows

package sshx

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
)

func openSSHAgent(ctx context.Context) (net.Conn, error) {
	socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socket == "" {
		return nil, fmt.Errorf("SSH Agent is unavailable: SSH_AUTH_SOCK is not set")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect SSH Agent: %w", err)
	}
	return connection, nil
}
