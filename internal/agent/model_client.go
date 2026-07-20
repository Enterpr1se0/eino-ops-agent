package agent

import (
	"errors"
	"strings"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/proxyx"

	"github.com/cloudwego/eino-ext/components/model/openai"
)

func chatModelConfig(cfg config.Model, timeout time.Duration) (*openai.ChatModelConfig, error) {
	result := &openai.ChatModelConfig{
		APIKey: cfg.APIKey, BaseURL: cfg.BaseURL, Model: cfg.Name, Timeout: timeout,
	}
	if cfg.ProxyURL == "" {
		return result, nil
	}
	client, err := proxyx.NewHTTPClient(cfg.ProxyURL, cfg.ProxyUsername, cfg.ProxyPassword, timeout)
	if err != nil {
		return nil, err
	}
	result.HTTPClient = client
	return result, nil
}

func redactModelError(cfg config.Model, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, secret := range []string{cfg.APIKey, cfg.ProxyPassword} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return errors.New(message)
}
