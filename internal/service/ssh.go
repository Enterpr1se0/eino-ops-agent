package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/sshx"
)

const maxProxyJumpDepth = 4

type sshConnectionBinding struct {
	Target sshHostBinding   `json:"target"`
	Jumps  []sshHostBinding `json:"jumps,omitempty"`
}

type sshHostBinding struct {
	ID              string `json:"id"`
	Address         string `json:"address"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	AuthType        string `json:"auth_type"`
	KnownHostsFile  string `json:"known_hosts_file,omitempty"`
	ProxyJumpHostID string `json:"proxy_jump_host_id,omitempty"`
	UpdatedAt       string `json:"updated_at"`
}

func (s *Service) resolveSSHConnection(ctx context.Context, target domain.Host) (sshx.ConnectionSpec, string, error) {
	connection := sshx.ConnectionSpec{Target: target}
	seen := map[string]struct{}{target.ID: {}}
	current := target
	nearestFirst := make([]domain.Host, 0, maxProxyJumpDepth)
	for current.ProxyJumpHostID != "" {
		if len(nearestFirst) >= maxProxyJumpDepth {
			return sshx.ConnectionSpec{}, "", fmt.Errorf("SSH ProxyJump chain exceeds %d hosts", maxProxyJumpDepth)
		}
		jump, err := s.store.GetHost(ctx, current.ProxyJumpHostID)
		if err != nil {
			return sshx.ConnectionSpec{}, "", fmt.Errorf("load ProxyJump host %q: %w", current.ProxyJumpHostID, err)
		}
		if _, duplicate := seen[jump.ID]; duplicate {
			return sshx.ConnectionSpec{}, "", fmt.Errorf("SSH ProxyJump chain contains a cycle at %q", jump.Name)
		}
		seen[jump.ID] = struct{}{}
		nearestFirst = append(nearestFirst, jump)
		current = jump
	}
	for index := len(nearestFirst) - 1; index >= 0; index-- {
		connection.Jumps = append(connection.Jumps, nearestFirst[index])
	}

	binding := sshConnectionBinding{Target: bindSSHHost(connection.Target)}
	for _, jump := range connection.Jumps {
		binding.Jumps = append(binding.Jumps, bindSSHHost(jump))
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return sshx.ConnectionSpec{}, "", err
	}
	digest := sha256.Sum256(data)
	return connection, hex.EncodeToString(digest[:]), nil
}

func bindSSHHost(host domain.Host) sshHostBinding {
	updated := ""
	if !host.UpdatedAt.IsZero() {
		updated = host.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return sshHostBinding{
		ID: host.ID, Address: host.Address, Port: host.Port, User: host.User,
		AuthType: host.AuthType, KnownHostsFile: host.KnownHostsFile,
		ProxyJumpHostID: host.ProxyJumpHostID, UpdatedAt: updated,
	}
}

func (s *Service) hydrateSSHConnection(connection sshx.ConnectionSpec, includeSudo bool) (sshx.ConnectionSpec, error) {
	target, err := s.hydrateHostSecrets(connection.Target, includeSudo)
	if err != nil {
		return sshx.ConnectionSpec{}, err
	}
	connection.Target = target
	for index := range connection.Jumps {
		jump, err := s.hydrateHostSecrets(connection.Jumps[index], false)
		if err != nil {
			return sshx.ConnectionSpec{}, fmt.Errorf("prepare ProxyJump credentials for %q: %w", connection.Jumps[index].Name, err)
		}
		connection.Jumps[index] = jump
	}
	return connection, nil
}

func bindSSHRequest(req *domain.ExecRequest, digest string) {
	req.SSHConnectionDigest = digest
}

func verifySSHRequestBinding(req domain.ExecRequest, digest string) error {
	if req.SSHConnectionDigest != digest {
		return fmt.Errorf("approved SSH connection changed after submission")
	}
	return nil
}
