package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerExposesMergedBackgroundTaskTools(t *testing.T) {
	ctx := context.Background()
	instance := New(nil, "test")
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := instance.server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	result, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	workspaceShellFound := false
	taskGetFound := false
	backgroundInputs := map[string]bool{"ssh_exec": false, "ssh_run_script": false}
	for _, registered := range result.Tools {
		for _, retired := range []string{"ssh_approval_status", "ssh_task_start", "ssh_task_status", "ssh_task_tail", "ssh_task_list"} {
			if registered.Name == retired {
				t.Fatalf("retired %s tool remains in the MCP catalog", retired)
			}
		}
		if registered.Name == "workspace_shell" {
			workspaceShellFound = true
		}
		if registered.Name == "ssh_task_get" {
			taskGetFound = true
		}
		if _, tracked := backgroundInputs[registered.Name]; tracked {
			schemaJSON, marshalErr := json.Marshal(registered.InputSchema)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			backgroundInputs[registered.Name] = strings.Contains(string(schemaJSON), `"background"`)
		}
	}
	if !workspaceShellFound {
		t.Fatal("workspace_shell is missing from the MCP catalog")
	}
	if !taskGetFound || !backgroundInputs["ssh_exec"] || !backgroundInputs["ssh_run_script"] {
		t.Fatalf("merged background task interface is incomplete: task_get=%v inputs=%#v", taskGetFound, backgroundInputs)
	}
}
