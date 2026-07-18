package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/store"

	"github.com/cloudwego/eino/adk"
	"github.com/cloudwego/eino/schema"
)

type scriptedAgentRunner struct {
	mu       sync.Mutex
	attempts [][]*adk.AgentEvent
	calls    int
	inputs   [][]*schema.Message
}

func (r *scriptedAgentRunner) Run(_ context.Context, messages []*schema.Message, _ ...adk.AgentRunOption) *adk.AsyncIterator[*adk.AgentEvent] {
	r.mu.Lock()
	index := r.calls
	r.calls++
	r.inputs = append(r.inputs, append([]*schema.Message(nil), messages...))
	var events []*adk.AgentEvent
	if index < len(r.attempts) {
		events = r.attempts[index]
	}
	r.mu.Unlock()
	iterator, generator := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	go func() {
		for _, event := range events {
			generator.Send(event)
		}
		generator.Close()
	}()
	return iterator
}

func (r *scriptedAgentRunner) snapshot() (int, [][]*schema.Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls, append([][]*schema.Message(nil), r.inputs...)
}

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

func TestQueryRetriesEmptyResponseWithoutDuplicatingUserMessage(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &scriptedAgentRunner{attempts: [][]*adk.AgentEvent{
		nil,
		{adk.EventFromMessage(schema.AssistantMessage("recovered", nil), nil, schema.Assistant, "")},
	}}
	runtime := &Runtime{runner: runner, store: st}
	var emitted []Event
	answer, err := runtime.Query(ctx, "session_retry", "continue", func(event Event) {
		emitted = append(emitted, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if answer != "recovered" {
		t.Fatalf("answer = %q", answer)
	}
	calls, inputs := runner.snapshot()
	if calls != 2 || len(inputs) != 2 || len(inputs[0]) != 1 || len(inputs[1]) != 1 {
		t.Fatalf("retry calls/inputs = %d %#v", calls, inputs)
	}
	messages, err := st.ListChatMessages(ctx, "session_retry", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Role != "user" || messages[0].Status != "completed" || messages[1].Role != "assistant" {
		t.Fatalf("stored messages = %#v", messages)
	}
	done := 0
	for _, event := range emitted {
		if event.Type == "done" {
			done++
		}
	}
	if done != 1 {
		t.Fatalf("done events = %d, events = %#v", done, emitted)
	}
}

func TestQueryRejectsRepeatedEmptyResponseAndExcludesFailedTurn(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &scriptedAgentRunner{attempts: [][]*adk.AgentEvent{nil, nil}}
	runtime := &Runtime{runner: runner, store: st}
	var emitted []Event
	_, err = runtime.Query(ctx, "session_empty", "continue", func(event Event) {
		emitted = append(emitted, event)
	})
	if !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("error = %v", err)
	}
	calls, _ := runner.snapshot()
	if calls != emptyResponseMaxAttempts {
		t.Fatalf("calls = %d", calls)
	}
	messages, err := st.ListChatMessages(ctx, "session_empty", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || messages[0].Role != "user" || messages[0].Status != "failed" {
		t.Fatalf("stored messages = %#v", messages)
	}
	modelMessages, err := st.ListChatModelMessages(ctx, "session_empty", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(modelMessages) != 0 {
		t.Fatalf("failed turn leaked into model history: %#v", modelMessages)
	}
	for _, event := range emitted {
		if event.Type == "done" {
			t.Fatalf("empty query emitted done: %#v", emitted)
		}
	}
}

func TestQueryDoesNotRetryAfterToolActivityWithoutFinalAnswer(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &scriptedAgentRunner{attempts: [][]*adk.AgentEvent{{
		adk.EventFromMessage(schema.ToolMessage("tool completed", "call-1"), nil, schema.Tool, "ssh_exec"),
	}}}
	runtime := &Runtime{runner: runner, store: st}
	var emitted []Event
	_, err = runtime.Query(ctx, "session_tool_empty", "inspect host", func(event Event) {
		emitted = append(emitted, event)
	})
	if !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("error = %v", err)
	}
	calls, _ := runner.snapshot()
	if calls != 1 {
		t.Fatalf("unsafe retry after tool activity: calls = %d", calls)
	}
	messages, err := st.ListChatMessages(ctx, "session_tool_empty", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Status != "completed" || messages[1].Role != "tool" {
		t.Fatalf("stored messages = %#v", messages)
	}
	for _, event := range emitted {
		if event.Type == "done" {
			t.Fatalf("incomplete query emitted done: %#v", emitted)
		}
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
