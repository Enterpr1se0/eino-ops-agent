package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
)

var ErrModelProviderUpstream = errors.New("model provider request failed")

const maxModelCatalogBytes = 2 << 20

type modelCatalogEntry struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Model string `json:"model"`
}

type resolvedModelProvider struct {
	ID      string
	Kind    string
	BaseURL string
	APIKey  string
}

func normalizeProviderBaseURL(value, kind string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		switch kind {
		case "openai":
			value = "https://api.openai.com/v1"
		case "deepseek":
			value = "https://api.deepseek.com"
		case "ollama":
			value = "http://127.0.0.1:11434/v1"
		case "openai_compatible":
			return "", fmt.Errorf("base_url is required for an OpenAI-compatible provider")
		default:
			return "", fmt.Errorf("invalid provider kind %q", kind)
		}
	}
	if !strings.Contains(value, "://") {
		scheme := "https://"
		hostPort := value
		if index := strings.IndexByte(hostPort, '/'); index >= 0 {
			hostPort = hostPort[:index]
		}
		hostname := hostPort
		if host, _, err := net.SplitHostPort(hostPort); err == nil {
			hostname = host
		}
		hostname = strings.Trim(hostname, "[]")
		ip := net.ParseIP(hostname)
		if strings.EqualFold(hostname, "localhost") || strings.HasSuffix(strings.ToLower(hostname), ".localhost") ||
			strings.HasSuffix(strings.ToLower(hostname), ".local") || !strings.Contains(hostname, ".") ||
			(ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())) {
			scheme = "http://"
		}
		value = scheme + value
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid base_url: enter a host or an absolute http/https URL, for example 127.0.0.1:11434/v1")
	}
	path := strings.TrimRight(parsed.Path, "/")
	for _, suffix := range []string{"/chat/completions", "/models"} {
		if strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	parsed.Path = strings.TrimRight(path, "/")
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func (s *Service) resolveModelProvider(ctx context.Context, providerID, kind string, inputBaseURL *string, inputAPIKey string) (resolvedModelProvider, error) {
	result := resolvedModelProvider{
		ID: strings.TrimSpace(providerID), Kind: strings.TrimSpace(kind), APIKey: strings.TrimSpace(inputAPIKey),
	}
	providerID = result.ID
	if providerID != "" {
		cfg, provider, err := s.ModelProviderConfig(ctx, providerID)
		if err != nil {
			return resolvedModelProvider{}, err
		}
		if result.Kind == "" {
			result.Kind = provider.Kind
		}
		result.BaseURL = cfg.BaseURL
		if result.APIKey == "" {
			result.APIKey = cfg.APIKey
		}
	}
	if inputBaseURL != nil {
		result.BaseURL = strings.TrimSpace(*inputBaseURL)
	}
	if result.Kind == "" {
		result.Kind = "openai_compatible"
	}
	if (result.Kind == "openai" || result.Kind == "deepseek") && result.APIKey == "" {
		return resolvedModelProvider{}, fmt.Errorf("api_key is required for %s", result.Kind)
	}
	normalizedBaseURL, err := normalizeProviderBaseURL(result.BaseURL, result.Kind)
	if err != nil {
		return resolvedModelProvider{}, err
	}
	result.BaseURL = normalizedBaseURL
	return result, nil
}

func (s *Service) ModelTestConfig(ctx context.Context, input domain.ModelTestInput) (config.Model, error) {
	resolved, err := s.resolveModelProvider(ctx, input.ID, input.Kind, input.BaseURL, input.APIKey)
	if err != nil {
		return config.Model{}, err
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		return config.Model{}, fmt.Errorf("model is required")
	}
	return config.Model{APIKey: resolved.APIKey, BaseURL: resolved.BaseURL, Name: model}, nil
}

func (s *Service) DiscoverModels(ctx context.Context, input domain.ModelDiscoveryInput, actor string) (domain.ModelCatalog, error) {
	resolved, err := s.resolveModelProvider(ctx, input.ID, input.Kind, input.BaseURL, input.APIKey)
	if err != nil {
		return domain.ModelCatalog{}, err
	}
	endpoint := resolved.BaseURL + "/models"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.ModelCatalog{}, fmt.Errorf("invalid model catalog endpoint: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if resolved.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+resolved.APIKey)
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return domain.ModelCatalog{}, fmt.Errorf("%w: %v", ErrModelProviderUpstream, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxModelCatalogBytes+1))
	if err != nil {
		return domain.ModelCatalog{}, fmt.Errorf("%w: read response: %v", ErrModelProviderUpstream, err)
	}
	if len(body) > maxModelCatalogBytes {
		return domain.ModelCatalog{}, fmt.Errorf("%w: response exceeds %d bytes", ErrModelProviderUpstream, maxModelCatalogBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail := strings.TrimSpace(string(body))
		if resolved.APIKey != "" {
			detail = strings.ReplaceAll(detail, resolved.APIKey, "[REDACTED]")
		}
		detail = s.redactor.Redact(detail)
		if len(detail) > 500 {
			detail = detail[:500]
		}
		return domain.ModelCatalog{}, fmt.Errorf("%w: HTTP %d: %s", ErrModelProviderUpstream, response.StatusCode, detail)
	}
	var payload struct {
		Data   []modelCatalogEntry `json:"data"`
		Models []modelCatalogEntry `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return domain.ModelCatalog{}, fmt.Errorf("%w: invalid JSON response", ErrModelProviderUpstream)
	}
	entries := append(payload.Data, payload.Models...)
	unique := make(map[string]struct{}, len(entries))
	models := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.ID)
		if name == "" {
			name = strings.TrimSpace(entry.Name)
		}
		if name == "" {
			name = strings.TrimSpace(entry.Model)
		}
		if name == "" || len(name) > 256 {
			continue
		}
		if _, exists := unique[name]; exists {
			continue
		}
		unique[name] = struct{}{}
		models = append(models, name)
	}
	if len(models) == 0 {
		return domain.ModelCatalog{}, fmt.Errorf("%w: response contains no model IDs", ErrModelProviderUpstream)
	}
	sort.Strings(models)
	s.audit(ctx, "", "model_catalog_discovered", actor, map[string]any{
		"provider_id": resolved.ID, "kind": resolved.Kind, "model_count": len(models),
	})
	return domain.ModelCatalog{Models: models, Count: len(models)}, nil
}
