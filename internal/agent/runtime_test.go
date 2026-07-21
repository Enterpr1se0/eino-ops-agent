package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

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

type blockingAgentRunner struct {
	started chan struct{}
}

func (r *blockingAgentRunner) Run(ctx context.Context, _ []*schema.Message, _ ...adk.AgentRunOption) *adk.AsyncIterator[*adk.AgentEvent] {
	iterator, generator := adk.NewAsyncIteratorPair[*adk.AgentEvent]()
	go func() {
		close(r.started)
		<-ctx.Done()
		generator.Close()
	}()
	return iterator
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

func TestProviderUsesConfiguredHTTPProxy(t *testing.T) {
	const proxyPassword = "runtime-proxy-secret"
	wantProxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:"+proxyPassword))
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		if r.Method != http.MethodPost || r.URL.Host != "model.invalid" || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected proxied model request: %s %s", r.Method, r.URL.String())
		}
		if got := r.Header.Get("Proxy-Authorization"); got != wantProxyAuth {
			t.Errorf("unexpected proxy authorization: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "id":"chatcmpl-proxy","object":"chat.completion","created":1,"model":"fixture-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":"Hello through proxy"},"finish_reason":"stop"}]
}`))
	}))
	defer proxy.Close()

	result, err := (&Runtime{}).TestProvider(context.Background(), config.Model{
		BaseURL: "http://model.invalid/v1", Name: "fixture-model", ProxyURL: proxy.URL,
		ProxyUsername: "proxy-user", ProxyPassword: proxyPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxyHits != 1 || result.Response != "Hello through proxy" {
		t.Fatalf("model test did not use the configured proxy: hits=%d result=%#v", proxyHits, result)
	}
}

func TestProviderRedactsCredentialEchoFromUpstreamError(t *testing.T) {
	const apiKey = "api-secret-value"
	const proxyPassword = "proxy-secret-value"
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, apiKey+" "+proxyPassword, http.StatusUnauthorized)
	}))
	defer proxy.Close()

	_, err := (&Runtime{}).TestProvider(context.Background(), config.Model{
		APIKey: apiKey, BaseURL: "http://model.invalid/v1", Name: "fixture-model", ProxyURL: proxy.URL,
		ProxyUsername: "proxy-user", ProxyPassword: proxyPassword,
	})
	if err == nil {
		t.Fatal("upstream error was accepted")
	}
	if strings.Contains(err.Error(), apiKey) || strings.Contains(err.Error(), proxyPassword) {
		t.Fatalf("model error exposed credentials: %v", err)
	}
}

func TestRuntimeTracksOneActiveRunPerSession(t *testing.T) {
	runtime := &Runtime{}
	runCtx, started := runtime.beginSession(context.Background(), "session_test")
	if !started {
		t.Fatal("first run was not registered")
	}
	if !runtime.IsSessionActive("session_test") {
		t.Fatal("registered run is not active")
	}
	if _, duplicateStarted := runtime.beginSession(context.Background(), "session_test"); duplicateStarted {
		t.Fatal("second concurrent run for the same session was accepted")
	}
	if !runtime.CancelSession("session_test") {
		t.Fatal("active run was not cancelled")
	}
	select {
	case <-runCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("registered run context was not cancelled")
	}
	runtime.endSession("session_test")
	if runtime.IsSessionActive("session_test") {
		t.Fatal("completed run remained active")
	}
	if runtime.CancelSession("session_test") {
		t.Fatal("inactive session reported a cancellation")
	}
}

func TestCancelSessionStopsQueryAndPersistsInterruption(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &blockingAgentRunner{started: make(chan struct{})}
	runtime := &Runtime{runner: runner, store: st}
	events := make(chan Event, 8)
	queryDone := make(chan error, 1)
	go func() {
		_, queryErr := runtime.Query(ctx, "session_cancel", "keep investigating", func(event Event) { events <- event })
		queryDone <- queryErr
	}()
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("Agent query did not start")
	}
	if !runtime.CancelSession("session_cancel") {
		t.Fatal("active Agent query was not cancelled")
	}
	select {
	case queryErr := <-queryDone:
		if !errors.Is(queryErr, context.Canceled) {
			t.Fatalf("query error = %v", queryErr)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled Agent query did not stop")
	}
	close(events)
	interrupted := 0
	for event := range events {
		if event.Type == "interrupted" && event.Content == interruptedRunMessage {
			interrupted++
		}
	}
	if interrupted != 1 {
		t.Fatalf("interrupted events = %d", interrupted)
	}
	messages, err := st.ListChatMessages(ctx, "session_cancel", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Role != "user" || messages[0].Status != "failed" || messages[1].Role != "assistant" || messages[1].Content != interruptedRunMessage {
		t.Fatalf("stored interruption = %#v", messages)
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

func TestQueryInjectsPersistedPlanBeforeCurrentUser(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, err = st.ReplaceAgentPlan(ctx, domain.AgentPlan{
		SessionID: "session_plan_context",
		Goal:      "Repair the API",
		Status:    "active",
		Steps: []domain.AgentPlanStep{
			{Number: 1, Title: "Inspect logs", Status: "completed", Evidence: "timeout observed"},
			{Number: 2, Title: "Fix timeout", Status: "in_progress"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := &scriptedAgentRunner{attempts: [][]*adk.AgentEvent{
		{adk.EventFromMessage(schema.AssistantMessage("continuing the current step", nil), nil, schema.Assistant, "")},
	}}
	runtime := &Runtime{runner: runner, store: st}
	if _, err := runtime.Query(ctx, "session_plan_context", "continue", nil); err != nil {
		t.Fatal(err)
	}
	_, inputs := runner.snapshot()
	if len(inputs) != 1 || len(inputs[0]) != 2 {
		t.Fatalf("model inputs = %#v", inputs)
	}
	planMessage, userMessage := inputs[0][0], inputs[0][1]
	if planMessage.Role != schema.System || !strings.Contains(planMessage.Content, "Repair the API") || !strings.Contains(planMessage.Content, `"status":"in_progress"`) || !strings.Contains(planMessage.Content, "untrusted data") {
		t.Fatalf("plan context = %#v", planMessage)
	}
	if strings.Contains(planMessage.Content, "session_plan_context") {
		t.Fatalf("plan context exposed the internal session id: %s", planMessage.Content)
	}
	if userMessage.Role != schema.User || userMessage.Content != "continue" {
		t.Fatalf("current user message = %#v", userMessage)
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
	if len(messages) != 2 || messages[0].Status != "failed" || messages[1].Role != "tool" {
		t.Fatalf("stored messages = %#v", messages)
	}
	for _, event := range emitted {
		if event.Type == "done" {
			t.Fatalf("incomplete query emitted done: %#v", emitted)
		}
	}
}

func TestNextQueryReceivesToolEvidenceFromFailedTurn(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/runtime.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runner := &scriptedAgentRunner{attempts: [][]*adk.AgentEvent{
		{adk.EventFromMessage(schema.ToolMessage(`{"status":"completed","stdout":"disk is healthy"}`, "call-1", schema.WithToolName("ssh_exec")), nil, schema.Tool, "ssh_exec")},
		{adk.EventFromMessage(schema.AssistantMessage("continued without repeating the check", nil), nil, schema.Assistant, "")},
	}}
	runtime := &Runtime{runner: runner, store: st}
	if _, err := runtime.Query(ctx, "session_tool_context", "inspect disk", nil); !errors.Is(err, ErrEmptyResponse) {
		t.Fatalf("first query error = %v", err)
	}
	answer, err := runtime.Query(ctx, "session_tool_context", "continue", nil)
	if err != nil {
		t.Fatal(err)
	}
	if answer != "continued without repeating the check" {
		t.Fatalf("answer = %q", answer)
	}
	_, inputs := runner.snapshot()
	if len(inputs) != 2 || len(inputs[1]) != 3 {
		t.Fatalf("model inputs = %#v", inputs)
	}
	if inputs[1][0].Role != schema.User || inputs[1][0].Content != "inspect disk" {
		t.Fatalf("failed turn user context = %#v", inputs[1][0])
	}
	if inputs[1][1].Role != schema.Assistant || !strings.Contains(inputs[1][1].Content, "Persisted operational tool evidence") || !strings.Contains(inputs[1][1].Content, "disk is healthy") {
		t.Fatalf("failed turn tool context = %#v", inputs[1][1])
	}
	if inputs[1][2].Role != schema.User || inputs[1][2].Content != "continue" {
		t.Fatalf("current query context = %#v", inputs[1][2])
	}
}

func TestBuildModelContextPreservesTurnBoundaries(t *testing.T) {
	history := []domain.ChatMessage{
		{Role: "user", Content: "install docker", Status: "completed"},
		{Role: "tool", ToolName: "ssh_exec", Content: `{"status":"completed","stdout":"docker installed"}`, Status: "completed"},
		{Role: "user", Content: "update mihomo", Status: "completed"},
		{Role: "tool", ToolName: "ssh_exec", Content: `{"status":"completed","stdout":"mihomo updated"}`, Status: "completed"},
		{Role: "user", Content: "hello", Status: "completed"},
	}
	messages, stats := buildModelContext(history, "what is the current state?")
	if len(messages) != 7 {
		t.Fatalf("model messages = %#v", messages)
	}
	wantRoles := []schema.RoleType{schema.User, schema.Assistant, schema.User, schema.Assistant, schema.User, schema.Assistant, schema.User}
	for index, role := range wantRoles {
		if messages[index].Role != role {
			t.Fatalf("message %d role = %s, want %s", index, messages[index].Role, role)
		}
	}
	if !strings.Contains(messages[1].Content, "docker installed") || !strings.Contains(messages[3].Content, "mihomo updated") {
		t.Fatalf("tool evidence was not retained: %#v", messages)
	}
	if messages[5].Content != incompleteTurnContext {
		t.Fatalf("incomplete turn marker = %q", messages[5].Content)
	}
	if stats.StoredTurns != 3 || stats.IncludedTurns != 3 || stats.ToolResults != 2 || stats.Truncated {
		t.Fatalf("context stats = %#v", stats)
	}
}

func TestBuildModelContextExcludesFailedTurnWithoutActivity(t *testing.T) {
	history := []domain.ChatMessage{
		{Role: "user", Content: "request that never reached the model", Status: "failed"},
		{Role: "user", Content: "successful request", Status: "completed"},
		{Role: "assistant", Content: "successful response", Status: "completed"},
	}
	messages, _ := buildModelContext(history, "next")
	if len(messages) != 3 || messages[0].Content != "successful request" || messages[1].Content != "successful response" || messages[2].Content != "next" {
		t.Fatalf("model messages = %#v", messages)
	}
}

func TestBuildMultimodalModelContextIncludesAllImages(t *testing.T) {
	historyImage := []byte("history-image")
	currentImageOne := []byte("current-image-one")
	currentImageTwo := []byte("current-image-two")
	history := []domain.ChatMessage{
		{Role: "user", Content: "previous screenshot", Status: "completed", Attachments: []domain.ChatAttachment{{Name: "previous.png", MIMEType: "image/png", Data: historyImage}}},
		{Role: "assistant", Content: "I can see it", Status: "completed"},
	}
	current := domain.ChatMessage{Role: "user", Content: "compare these", Attachments: []domain.ChatAttachment{
		{Name: "one.jpg", MIMEType: "image/jpeg", Data: currentImageOne},
		{Name: "two.webp", MIMEType: "image/webp", Data: currentImageTwo},
	}}
	messages, stats := buildMultimodalModelContext(history, current)
	if len(messages) != 3 || len(messages[0].UserInputMultiContent) != 2 || len(messages[2].UserInputMultiContent) != 3 {
		t.Fatalf("multimodal messages = %#v", messages)
	}
	if messages[0].UserInputMultiContent[0].Text != "previous screenshot" || messages[2].UserInputMultiContent[0].Text != "compare these" {
		t.Fatalf("multimodal text parts = %#v", messages)
	}
	wantImages := [][]byte{historyImage, currentImageOne, currentImageTwo}
	imageParts := []schema.MessageInputPart{
		messages[0].UserInputMultiContent[1], messages[2].UserInputMultiContent[1], messages[2].UserInputMultiContent[2],
	}
	for index, part := range imageParts {
		if part.Type != schema.ChatMessagePartTypeImageURL || part.Image == nil || part.Image.Base64Data == nil {
			t.Fatalf("image part %d = %#v", index, part)
		}
		decoded, err := base64.StdEncoding.DecodeString(*part.Image.Base64Data)
		if err != nil || string(decoded) != string(wantImages[index]) {
			t.Fatalf("image part %d data = %q, err = %v", index, decoded, err)
		}
	}
	if stats.Images != 3 || stats.ImageBytes != int64(len(historyImage)+len(currentImageOne)+len(currentImageTwo)) || stats.Truncated {
		t.Fatalf("multimodal context stats = %#v", stats)
	}
}

func TestTruncateModelTextKeepsValidUTF8AndBothEnds(t *testing.T) {
	value := strings.Repeat("开头", 100) + " middle " + strings.Repeat("结尾", 100)
	truncated := truncateModelText(value, 180)
	if !utf8.ValidString(truncated) || len(truncated) > 180 {
		t.Fatalf("invalid truncation length=%d value=%q", len(truncated), truncated)
	}
	if !strings.HasPrefix(truncated, "开头") || !strings.HasSuffix(truncated, "结尾") || !strings.Contains(truncated, "truncated") {
		t.Fatalf("truncation did not preserve both ends: %q", truncated)
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
	nested := runtime.enrichToolContent(ctx, `{"task":{"id":"task_display","run_id":"run_display","status":"failed"},"result":{"run_id":"run_display","status":"failed","stderr":"command failed"}}`)
	if !strings.Contains(nested, `"_display"`) || !strings.Contains(nested, `"stderr":"command failed"`) {
		t.Fatalf("nested task result was not enriched without losing stderr: %s", nested)
	}
}
