package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/proxyx"
)

const maxWebSearchResponseBytes = 2 << 20

var (
	ErrWebSearchDisabled = errors.New("web search is disabled")
	ErrWebSearchUpstream = errors.New("web search provider request failed")
	webSearchDomain      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

type resolvedWebSearchSettings struct {
	domain.WebSearchSettings
	APIKey        string
	ProxyPassword string
}

type tavilySearchRequest struct {
	Query          string   `json:"query"`
	SearchDepth    string   `json:"search_depth"`
	MaxResults     int      `json:"max_results"`
	TimeRange      string   `json:"time_range,omitempty"`
	IncludeDomains []string `json:"include_domains,omitempty"`
	ExcludeDomains []string `json:"exclude_domains,omitempty"`
	IncludeAnswer  bool     `json:"include_answer"`
	IncludeRaw     bool     `json:"include_raw_content"`
}

type tavilySearchResponse struct {
	Results      []domain.WebSearchResult `json:"results"`
	ResponseTime float64                  `json:"response_time"`
}

func (s *Service) WebSearchSettings(ctx context.Context) (domain.WebSearchSettings, error) {
	settings, err := s.store.GetWebSearchSettings(ctx)
	if err != nil {
		return domain.WebSearchSettings{}, err
	}
	return publicWebSearchSettings(settings), nil
}

func (s *Service) SaveWebSearchSettings(ctx context.Context, input domain.WebSearchSettingsInput, actor string) (domain.WebSearchSettings, error) {
	current, err := s.store.GetWebSearchSettings(ctx)
	if err != nil {
		return domain.WebSearchSettings{}, err
	}
	baseURL, err := normalizeTavilyBaseURL(input.BaseURL)
	if err != nil {
		return domain.WebSearchSettings{}, err
	}
	proxyURL, err := normalizeWebSearchProxyURL(input.ProxyURL)
	if err != nil {
		return domain.WebSearchSettings{}, err
	}
	if input.TimeoutSeconds < domain.MinWebSearchTimeoutSeconds || input.TimeoutSeconds > domain.MaxWebSearchTimeoutSeconds {
		return domain.WebSearchSettings{}, fmt.Errorf("timeout_seconds must be between %d and %d", domain.MinWebSearchTimeoutSeconds, domain.MaxWebSearchTimeoutSeconds)
	}
	if input.MaxResults < domain.MinWebSearchMaxResults || input.MaxResults > domain.MaxWebSearchMaxResults {
		return domain.WebSearchSettings{}, fmt.Errorf("max_results must be between %d and %d", domain.MinWebSearchMaxResults, domain.MaxWebSearchMaxResults)
	}

	apiKeyCipher := current.APIKeyCipher
	if input.ClearAPIKey {
		apiKeyCipher = ""
	}
	if apiKey := strings.TrimSpace(input.APIKey); apiKey != "" {
		apiKeyCipher, err = s.encryptor.Encrypt([]byte(apiKey))
		if err != nil {
			return domain.WebSearchSettings{}, err
		}
	}
	if input.Enabled && apiKeyCipher == "" {
		return domain.WebSearchSettings{}, fmt.Errorf("Tavily API key is required when web search is enabled")
	}

	proxyUsername := strings.TrimSpace(input.ProxyUsername)
	proxyPasswordCipher := current.ProxyPasswordCipher
	if input.ClearProxyPassword {
		proxyPasswordCipher = ""
	}
	if proxyURL == "" || proxyUsername == "" {
		proxyUsername = ""
		proxyPasswordCipher = ""
	} else if input.ProxyPassword != "" {
		proxyPasswordCipher, err = s.encryptor.Encrypt([]byte(input.ProxyPassword))
		if err != nil {
			return domain.WebSearchSettings{}, err
		}
	}

	saved, err := s.store.SaveWebSearchSettings(ctx, domain.WebSearchSettings{
		Enabled: input.Enabled, Provider: "tavily", BaseURL: baseURL, APIKeyCipher: apiKeyCipher,
		ProxyURL: proxyURL, ProxyUsername: proxyUsername, ProxyPasswordCipher: proxyPasswordCipher,
		TimeoutSeconds: input.TimeoutSeconds, MaxResults: input.MaxResults,
	})
	if err != nil {
		return domain.WebSearchSettings{}, err
	}
	s.audit(ctx, "", "web_search_settings_updated", actor, map[string]any{
		"enabled": saved.Enabled, "provider": saved.Provider, "base_url": saved.BaseURL,
		"proxy_configured": saved.ProxyURL != "", "timeout_seconds": saved.TimeoutSeconds, "max_results": saved.MaxResults,
	})
	return publicWebSearchSettings(saved), nil
}

func decorateWebSearchSettings(settings domain.WebSearchSettings) domain.WebSearchSettings {
	if settings.Provider == "" {
		settings.Provider = "tavily"
	}
	if settings.BaseURL == "" {
		settings.BaseURL = domain.DefaultWebSearchBaseURL
	}
	if settings.TimeoutSeconds == 0 {
		settings.TimeoutSeconds = domain.DefaultWebSearchTimeoutSeconds
	}
	if settings.MaxResults == 0 {
		settings.MaxResults = domain.DefaultWebSearchMaxResults
	}
	settings.HasAPIKey = settings.APIKeyCipher != ""
	settings.HasProxyPassword = settings.ProxyPasswordCipher != ""
	return settings
}

func publicWebSearchSettings(settings domain.WebSearchSettings) domain.WebSearchSettings {
	settings = decorateWebSearchSettings(settings)
	settings.APIKeyCipher = ""
	settings.ProxyPasswordCipher = ""
	return settings
}

func (s *Service) resolveWebSearchSettings(ctx context.Context) (resolvedWebSearchSettings, error) {
	settings, err := s.store.GetWebSearchSettings(ctx)
	if err != nil {
		return resolvedWebSearchSettings{}, err
	}
	settings = decorateWebSearchSettings(settings)
	if !settings.Enabled {
		return resolvedWebSearchSettings{}, ErrWebSearchDisabled
	}
	if settings.APIKeyCipher == "" {
		return resolvedWebSearchSettings{}, fmt.Errorf("%w: Tavily API key is not configured", ErrWebSearchDisabled)
	}
	apiKey, err := s.encryptor.Decrypt(settings.APIKeyCipher)
	if err != nil {
		return resolvedWebSearchSettings{}, fmt.Errorf("decrypt Tavily API key: %w", err)
	}
	proxyPassword, err := s.encryptor.Decrypt(settings.ProxyPasswordCipher)
	if err != nil {
		return resolvedWebSearchSettings{}, fmt.Errorf("decrypt web search proxy password: %w", err)
	}
	return resolvedWebSearchSettings{WebSearchSettings: settings, APIKey: string(apiKey), ProxyPassword: string(proxyPassword)}, nil
}

func (s *Service) SearchWeb(ctx context.Context, input domain.WebSearchRequest, actor string) (domain.WebSearchResponse, error) {
	settings, err := s.resolveWebSearchSettings(ctx)
	if err != nil {
		return domain.WebSearchResponse{}, err
	}
	request, err := normalizeWebSearchRequest(input, settings.MaxResults)
	if err != nil {
		return domain.WebSearchResponse{}, err
	}
	payload, err := json.Marshal(tavilySearchRequest{
		Query: request.Query, SearchDepth: "basic", MaxResults: request.MaxResults, TimeRange: request.TimeRange,
		IncludeDomains: request.IncludeDomains, ExcludeDomains: request.ExcludeDomains, IncludeAnswer: false, IncludeRaw: false,
	})
	if err != nil {
		return domain.WebSearchResponse{}, err
	}
	endpoint := strings.TrimRight(settings.BaseURL, "/") + "/search"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return domain.WebSearchResponse{}, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+settings.APIKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("User-Agent", "OpsPilot-WebSearch/1.0")

	client, err := webSearchHTTPClient(settings)
	if err != nil {
		return domain.WebSearchResponse{}, err
	}
	queryDigest := sha256.Sum256([]byte(request.Query))
	started := time.Now()
	response, err := client.Do(httpRequest)
	if err != nil {
		s.audit(ctx, "", "web_search_failed", actor, map[string]any{
			"provider": "tavily", "query_sha256": hex.EncodeToString(queryDigest[:]), "duration_ms": time.Since(started).Milliseconds(),
		})
		return domain.WebSearchResponse{}, fmt.Errorf("%w: %s", ErrWebSearchUpstream, s.scrubWebSearchText(err.Error(), settings))
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxWebSearchResponseBytes+1))
	if err != nil {
		return domain.WebSearchResponse{}, fmt.Errorf("%w: read response: %v", ErrWebSearchUpstream, err)
	}
	if len(body) > maxWebSearchResponseBytes {
		return domain.WebSearchResponse{}, fmt.Errorf("%w: response exceeded 2 MiB", ErrWebSearchUpstream)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := boundedWebSearchText(s.scrubWebSearchText(string(body), settings), 1000)
		return domain.WebSearchResponse{}, fmt.Errorf("%w: Tavily returned %s: %s", ErrWebSearchUpstream, response.Status, message)
	}
	var decoded tavilySearchResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return domain.WebSearchResponse{}, fmt.Errorf("%w: decode response: %v", ErrWebSearchUpstream, err)
	}
	results := make([]domain.WebSearchResult, 0, min(len(decoded.Results), request.MaxResults))
	for _, result := range decoded.Results {
		if len(results) == request.MaxResults {
			break
		}
		parsed, err := url.Parse(strings.TrimSpace(result.URL))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			continue
		}
		if containsWebSearchSecret(parsed.String(), settings) {
			continue
		}
		result.Title = boundedWebSearchText(s.scrubWebSearchText(result.Title, settings), 500)
		result.URL = boundedWebSearchText(parsed.String(), 2048)
		result.Content = boundedWebSearchText(s.scrubWebSearchText(result.Content, settings), 4000)
		result.PublishedDate = boundedWebSearchText(s.scrubWebSearchText(result.PublishedDate, settings), 100)
		results = append(results, result)
	}
	s.audit(ctx, "", "web_search_completed", actor, map[string]any{
		"provider": "tavily", "query_sha256": hex.EncodeToString(queryDigest[:]), "result_count": len(results),
		"duration_ms": time.Since(started).Milliseconds(), "proxy_used": settings.ProxyURL != "",
	})
	return domain.WebSearchResponse{
		Query: request.Query, Provider: "tavily", Results: results, ResponseTime: decoded.ResponseTime, ContentIsUntrusted: true,
	}, nil
}

func containsWebSearchSecret(value string, settings resolvedWebSearchSettings) bool {
	return settings.APIKey != "" && strings.Contains(value, settings.APIKey) ||
		settings.ProxyPassword != "" && strings.Contains(value, settings.ProxyPassword)
}

func (s *Service) scrubWebSearchText(value string, settings resolvedWebSearchSettings) string {
	for _, secret := range []string{settings.APIKey, settings.ProxyPassword} {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	if s.redactor != nil {
		value = s.redactor.Redact(value)
	}
	return value
}

func normalizeTavilyBaseURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = domain.DefaultWebSearchBaseURL
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid Tavily base_url")
	}
	parsed.Path = strings.TrimSuffix(strings.TrimRight(parsed.Path, "/"), "/search")
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func normalizeWebSearchProxyURL(value string) (string, error) {
	normalized, err := proxyx.NormalizeURL(value)
	if err != nil {
		return "", fmt.Errorf("invalid web search proxy URL: %w", err)
	}
	return normalized, nil
}

func webSearchHTTPClient(settings resolvedWebSearchSettings) (*http.Client, error) {
	timeout := time.Duration(settings.TimeoutSeconds) * time.Second
	if settings.ProxyURL != "" {
		return proxyx.NewHTTPClient(settings.ProxyURL, settings.ProxyUsername, settings.ProxyPassword, timeout)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = timeout
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func normalizeWebSearchRequest(input domain.WebSearchRequest, configuredMax int) (domain.WebSearchRequest, error) {
	input.Query = strings.TrimSpace(input.Query)
	if input.Query == "" || len(input.Query) > 2000 {
		return domain.WebSearchRequest{}, fmt.Errorf("query is required and must not exceed 2000 bytes")
	}
	if input.MaxResults == 0 {
		input.MaxResults = configuredMax
	}
	if input.MaxResults < domain.MinWebSearchMaxResults || input.MaxResults > configuredMax {
		return domain.WebSearchRequest{}, fmt.Errorf("max_results must be between %d and %d", domain.MinWebSearchMaxResults, configuredMax)
	}
	input.TimeRange = strings.ToLower(strings.TrimSpace(input.TimeRange))
	if input.TimeRange != "" && input.TimeRange != "day" && input.TimeRange != "week" && input.TimeRange != "month" && input.TimeRange != "year" {
		return domain.WebSearchRequest{}, fmt.Errorf("time_range must be day, week, month, or year")
	}
	var err error
	if input.IncludeDomains, err = normalizeWebSearchDomains(input.IncludeDomains); err != nil {
		return domain.WebSearchRequest{}, fmt.Errorf("include_domains: %w", err)
	}
	if input.ExcludeDomains, err = normalizeWebSearchDomains(input.ExcludeDomains); err != nil {
		return domain.WebSearchRequest{}, fmt.Errorf("exclude_domains: %w", err)
	}
	return input, nil
}

func normalizeWebSearchDomains(values []string) ([]string, error) {
	if len(values) > 10 {
		return nil, fmt.Errorf("at most 10 domains are allowed")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if !webSearchDomain.MatchString(value) || strings.Contains(value, "..") {
			return nil, fmt.Errorf("invalid domain %q", value)
		}
		if _, exists := seen[value]; !exists {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result, nil
}

func boundedWebSearchText(value string, limit int) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			return -1
		}
		return character
	}, strings.TrimSpace(value))
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8RuneStart(value[limit]) {
		limit--
	}
	return value[:limit] + "\n[CONTENT TRUNCATED]"
}

func utf8RuneStart(value byte) bool {
	return value&0xc0 != 0x80
}
