package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"eino-ops-agent/internal/domain"

	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestManagedMCPServerInjectsNamespacedToolAndCanBeDisabled(t *testing.T) {
	svc, _, _ := newTestService(t)
	t.Cleanup(svc.CloseMCPServers)
	remote := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1.0.0"}, nil)
	type echoInput struct {
		Message string `json:"message" jsonschema:"message to echo"`
	}
	type echoOutput struct {
		Echo string `json:"echo"`
	}
	mcp.AddTool(remote, &mcp.Tool{Name: "echo.message", Description: "Echo one message."},
		func(_ context.Context, _ *mcp.CallToolRequest, input echoInput) (*mcp.CallToolResult, echoOutput, error) {
			return nil, echoOutput{Echo: input.Message}, nil
		})
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, nil)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		streamable.ServeHTTP(w, r)
	}))
	defer httpServer.Close()

	server, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{
		Name: "Fixture MCP", Transport: domain.MCPTransportStreamableHTTP, URL: httpServer.URL,
		Headers: map[string]string{"Authorization": "Bearer fixture-secret"}, Enabled: true,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if server.Status != "ready" || server.ToolCount != 1 || !strings.HasPrefix(server.Tools[0].ExposedName, "mcp__") {
		t.Fatalf("unexpected MCP runtime: %#v", server)
	}
	encoded, _ := json.Marshal(server)
	if strings.Contains(string(encoded), "fixture-secret") || strings.Contains(string(encoded), "secrets_cipher") {
		t.Fatalf("MCP response exposed secret material: %s", encoded)
	}

	loaded := svc.MCPTools()
	if len(loaded) != 1 {
		t.Fatalf("loaded MCP tools=%d, want 1", len(loaded))
	}
	invokable, ok := loaded[0].(tool.InvokableTool)
	if !ok {
		t.Fatalf("MCP tool is not invokable: %T", loaded[0])
	}
	output, err := invokable.InvokableRun(context.Background(), `{"message":"hello"}`)
	if err != nil || !strings.Contains(output, "hello") {
		t.Fatalf("MCP invocation output=%q err=%v", output, err)
	}

	server, err = svc.SetMCPServerEnabled(context.Background(), server.ID, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	if server.Status != "disabled" || len(svc.MCPTools()) != 0 {
		t.Fatalf("disabled MCP server remains loaded: %#v", server)
	}
	if _, err := invokable.InvokableRun(context.Background(), `{"message":"again"}`); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("stale MCP wrapper remained callable: %v", err)
	}
}

func TestMCPServerEditPreservesEncryptedSecretsWhenOmitted(t *testing.T) {
	svc, _, _ := newTestService(t)
	created, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{
		Name: "Local package tools", Transport: domain.MCPTransportStdio, Command: "npx", Args: []string{"-y", "fixture"},
		Env: map[string]string{"TOKEN": "top-secret"}, Enabled: false,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{
		ID: created.ID, Name: "Renamed package tools", Transport: domain.MCPTransportStdio,
		Command: "npx", Args: []string{"-y", "fixture"}, Enabled: false,
	}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.EnvKeys) != 1 || updated.EnvKeys[0] != "TOKEN" {
		t.Fatalf("blank edit erased MCP secrets: %#v", updated)
	}
	stored, err := svc.store.GetMCPServer(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := svc.decryptMCPSecrets(stored.SecretsCipher)
	if err != nil || secrets.Env["TOKEN"] != "top-secret" {
		t.Fatalf("encrypted MCP secret did not round-trip: %#v err=%v", secrets, err)
	}
}
