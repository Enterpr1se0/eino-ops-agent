package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"eino-ops-agent/internal/domain"
)

func TestTavilyWebSearchUsesConfiguredProxyAndKeepsCredentialsEncrypted(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		http.Error(w, "request bypassed proxy", http.StatusBadGateway)
	}))
	defer target.Close()

	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/search" {
			t.Errorf("unexpected proxied request: %s %s", r.Method, r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer tvly-test-secret" {
			t.Errorf("missing Tavily bearer token: %q", r.Header.Get("Authorization"))
		}
		wantProxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
		if r.Header.Get("Proxy-Authorization") != wantProxyAuth {
			t.Errorf("unexpected proxy authorization: %q", r.Header.Get("Proxy-Authorization"))
		}
		var input tavilySearchRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		if input.Query != "current Go release" || input.MaxResults != 2 || input.TimeRange != "month" || len(input.IncludeDomains) != 1 || input.IncludeDomains[0] != "go.dev" || input.IncludeAnswer || input.IncludeRaw {
			t.Errorf("unexpected Tavily request: %#v", input)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"title":"Go release","url":"https://go.dev/doc/devel/release","content":"reflected tvly-test-secret and proxy-secret","score":0.9,"published_date":"2026-07-01"}],"response_time":0.12}`))
	}))
	defer proxy.Close()

	saved, err := svc.SaveWebSearchSettings(ctx, domain.WebSearchSettingsInput{
		Enabled: true, BaseURL: target.URL, APIKey: "tvly-test-secret", ProxyURL: proxy.URL,
		ProxyUsername: "proxy-user", ProxyPassword: "proxy-secret", TimeoutSeconds: 10, MaxResults: 4,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !saved.HasAPIKey || !saved.HasProxyPassword || saved.APIKeyCipher != "" || saved.ProxyPasswordCipher != "" {
		t.Fatalf("public settings exposed or lost credential state: %#v", saved)
	}
	serialized, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "tvly-test-secret") || strings.Contains(string(serialized), "proxy-secret") {
		t.Fatalf("settings JSON exposed credentials: %s", serialized)
	}
	stored, err := svc.store.GetWebSearchSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.APIKeyCipher == "" || stored.APIKeyCipher == "tvly-test-secret" || stored.ProxyPasswordCipher == "" || stored.ProxyPasswordCipher == "proxy-secret" {
		t.Fatalf("credentials were not encrypted at rest: %#v", stored)
	}

	result, err := svc.SearchWeb(ctx, domain.WebSearchRequest{
		Query: "current Go release", MaxResults: 2, TimeRange: "month", IncludeDomains: []string{"GO.DEV"},
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if proxyHits.Load() != 1 || targetHits.Load() != 0 {
		t.Fatalf("proxy routing failed: proxy=%d target=%d", proxyHits.Load(), targetHits.Load())
	}
	if result.Provider != "tavily" || !result.ContentIsUntrusted || len(result.Results) != 1 || result.Results[0].Title != "Go release" {
		t.Fatalf("unexpected normalized result: %#v", result)
	}
	if strings.Contains(result.Results[0].Content, "tvly-test-secret") || strings.Contains(result.Results[0].Content, "proxy-secret") {
		t.Fatalf("provider response exposed configured credentials: %#v", result.Results[0])
	}

	preserved, err := svc.SaveWebSearchSettings(ctx, domain.WebSearchSettingsInput{
		Enabled: false, BaseURL: target.URL, ProxyURL: proxy.URL, ProxyUsername: "proxy-user",
		TimeoutSeconds: 10, MaxResults: 4,
	}, "test")
	if err != nil || !preserved.HasAPIKey || !preserved.HasProxyPassword {
		t.Fatalf("blank secret input did not preserve credentials: settings=%#v err=%v", preserved, err)
	}
	cleared, err := svc.SaveWebSearchSettings(ctx, domain.WebSearchSettingsInput{
		Enabled: false, BaseURL: target.URL, ProxyURL: proxy.URL, ProxyUsername: "proxy-user", ClearProxyPassword: true,
		TimeoutSeconds: 10, MaxResults: 4,
	}, "test")
	if err != nil || !cleared.HasAPIKey || cleared.HasProxyPassword {
		t.Fatalf("proxy password was not cleared independently: settings=%#v err=%v", cleared, err)
	}
}

func TestWebSearchValidatesConfigurationAndInput(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.SearchWeb(ctx, domain.WebSearchRequest{Query: "test"}, "test"); !errors.Is(err, ErrWebSearchDisabled) {
		t.Fatalf("disabled search returned %v", err)
	}
	if _, err := svc.SaveWebSearchSettings(ctx, domain.WebSearchSettingsInput{
		Enabled: true, BaseURL: domain.DefaultWebSearchBaseURL, TimeoutSeconds: 20, MaxResults: 5,
	}, "test"); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("enabled search without key was accepted: %v", err)
	}
	if _, err := normalizeWebSearchRequest(domain.WebSearchRequest{Query: "test", IncludeDomains: []string{"https://example.com/path"}}, 5); err == nil {
		t.Fatal("domain with scheme and path was accepted")
	}
	defaulted, err := normalizeWebSearchRequest(domain.WebSearchRequest{Query: "test"}, 17)
	if err != nil || defaulted.MaxResults != 17 {
		t.Fatalf("omitted max_results did not use the administrator default: request=%#v err=%v", defaulted, err)
	}
	if _, err := normalizeWebSearchRequest(domain.WebSearchRequest{Query: "test", MaxResults: 18}, 17); err == nil {
		t.Fatal("max_results above the administrator limit was accepted")
	}
	for _, proxyURL := range []string{
		"http://127.0.0.1:7890", "https://proxy.example:8443", "socks5://127.0.0.1:1080", "socks5h://proxy.example:1080",
	} {
		if normalized, err := normalizeWebSearchProxyURL(proxyURL); err != nil || normalized != proxyURL {
			t.Errorf("proxy URL %q normalized to %q with error %v", proxyURL, normalized, err)
		}
	}
	if _, err := normalizeWebSearchProxyURL("ftp://proxy.example:21"); err == nil {
		t.Fatal("unsupported proxy scheme was accepted")
	}
}
