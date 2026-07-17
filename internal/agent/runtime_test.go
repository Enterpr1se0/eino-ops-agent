package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/store"
)

func TestProviderSendsHelloAndAcceptsNonEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var request struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if len(request.Messages) != 1 || request.Messages[0].Content != "Hello" {
			t.Fatalf("unexpected test prompt %#v", request.Messages)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "id":"chatcmpl-test","object":"chat.completion","created":1,"model":"fixture-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":"Hello from fixture"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`))
	}))
	defer server.Close()

	result, err := (&Runtime{}).TestProvider(context.Background(), config.Model{
		APIKey: "fixture-key", BaseURL: server.URL + "/v1", Name: "fixture-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Response != "Hello from fixture" || result.Model != "fixture-model" {
		t.Fatalf("unexpected test result %#v", result)
	}
}

func TestProviderRejectsEmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "id":"chatcmpl-test","object":"chat.completion","created":1,"model":"fixture-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"stop"}]
}`))
	}))
	defer server.Close()

	_, err := (&Runtime{}).TestProvider(context.Background(), config.Model{
		BaseURL: server.URL + "/v1", Name: "fixture-model",
	})
	if err == nil {
		t.Fatal("empty model response was accepted")
	}
}

func TestRuntimeTracksOneActiveRunPerSession(t *testing.T) {
	runtime := &Runtime{}
	if !runtime.beginSession("session_test") {
		t.Fatal("first run was not registered")
	}
	if !runtime.IsSessionActive("session_test") {
		t.Fatal("registered run is not active")
	}
	if runtime.beginSession("session_test") {
		t.Fatal("second concurrent run for the same session was accepted")
	}
	runtime.endSession("session_test")
	if runtime.IsSessionActive("session_test") {
		t.Fatal("completed run remained active")
	}
}

func TestToolHistoryIsEnrichedWithCompleteAuditedCommand(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.UpsertHost(ctx, domain.Host{ID: "host_display", Name: "display", Address: "127.0.0.1", Port: 22, User: "ops", AuthType: "agent", SudoMode: "none"}); err != nil {
		t.Fatal(err)
	}
	run := domain.Run{
		ID: "run_display", HostID: "host_display", Risk: domain.RiskReadOnly, Status: "completed",
		RequestJSON:   `{"host_id":"host_display","mode":"program","program":"journalctl","args":["-u","demo service","-n","100"],"cwd":"/srv/demo","reason":"inspect logs"}`,
		RequestDigest: "digest", StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC(),
	}
	if err := st.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{store: st}
	enriched := runtime.enrichToolContent(ctx, `{"run_id":"run_display","status":"completed"}`)
	var payload struct {
		Display struct {
			HostID  string         `json:"host_id"`
			Request map[string]any `json:"request"`
		} `json:"_display"`
	}
	if err := json.Unmarshal([]byte(enriched), &payload); err != nil {
		t.Fatal(err)
	}
	args, _ := payload.Display.Request["args"].([]any)
	if payload.Display.HostID != "host_display" || payload.Display.Request["program"] != "journalctl" || len(args) != 4 || args[1] != "demo service" {
		t.Fatalf("complete command was not preserved in Tool display payload: %s", enriched)
	}
}
