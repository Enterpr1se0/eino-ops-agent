package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestServerDoesNotExposeRetiredApprovalStatusTool(t *testing.T) {
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
	for _, registered := range result.Tools {
		if registered.Name == "ssh_approval_status" {
			t.Fatal("retired ssh_approval_status tool remains in the MCP catalog")
		}
		if registered.Name == "workspace_shell" {
			workspaceShellFound = true
		}
	}
	if !workspaceShellFound {
		t.Fatal("workspace_shell is missing from the MCP catalog")
	}
}
