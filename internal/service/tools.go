package service

import (
	"context"
	"fmt"
	"regexp"
)

var agentToolNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,160}$`)

func (s *Service) AgentToolStates(ctx context.Context) (map[string]bool, error) {
	return s.store.AgentToolStates(ctx)
}

func (s *Service) SetAgentToolEnabled(ctx context.Context, name string, enabled bool, actor string) error {
	if !agentToolNameRE.MatchString(name) {
		return fmt.Errorf("invalid agent function name")
	}
	if err := s.store.SetAgentToolEnabled(ctx, name, enabled); err != nil {
		return err
	}
	eventType := "agent_function_disabled"
	if enabled {
		eventType = "agent_function_enabled"
	}
	s.audit(ctx, "", eventType, actor, map[string]any{"function_name": name})
	return nil
}
