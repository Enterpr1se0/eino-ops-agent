package mcpserver

import (
	"context"

	"eino-ops-agent/internal/agent"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/skills"
	"eino-ops-agent/internal/sshx"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	server *mcp.Server
}

func New(svc *service.Service, version string) *Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "eino-ops-agent", Version: version}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "ssh_host_inspect", Description: "Read-only inspection of a registered SSH host."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.HostInput) (*mcp.CallToolResult, sshx.HostInfo, error) {
			output, err := svc.ProbeHost(ctx, input.HostID)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_host_list", Description: "List registered host IDs, names, authentication types, and managed sudo modes without connection details or credentials."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, agent.HostListOutput, error) {
			hosts, err := svc.ListHostCapabilities(ctx)
			return nil, agent.HostListOutput{Hosts: hosts}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_exec", Description: "Execute one remote program with separate arguments through deterministic policy, approval, and audit controls."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ExecInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.Submit(ctx, execRequest(input), "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_run_script", Description: "Analyze and run a Bash script. State changes return approval_required without executing."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ScriptInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.Submit(ctx, scriptRequest(input), "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_start", Description: "Start a cancellable long-running SSH command."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ExecInput) (*mcp.CallToolResult, domain.Task, error) {
			output, err := svc.StartTask(ctx, execRequest(input), "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_status", Description: "Read task status and bounded redacted output."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.TaskInput) (*mcp.CallToolResult, agent.TaskOutput, error) {
			task, result, taskErr, err := svc.GetTask(input.TaskID)
			return nil, agent.TaskOutput{Task: task, Result: result, Error: taskErr}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_tail", Description: "Read the latest bounded redacted output accumulated by a running SSH task."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.TaskInput) (*mcp.CallToolResult, agent.TaskOutput, error) {
			task, result, taskErr, err := svc.GetTask(input.TaskID)
			return nil, agent.TaskOutput{Task: task, Result: result, Error: taskErr}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_cancel", Description: "Cancel a running SSH task."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.TaskInput) (*mcp.CallToolResult, map[string]any, error) {
			err := svc.CancelTask(input.TaskID, "mcp-client")
			return nil, map[string]any{"task_id": input.TaskID, "cancelled": err == nil}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_read", Description: "Read a bounded remote file. Credential paths are denied."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileReadInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ReadFile(ctx, input.HostID, input.Path, input.MaxBytes, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_list", Description: "List a remote directory without changing it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileListInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ListFiles(ctx, input.HostID, input.Path, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_write", Description: "Request replacement of a remote file. Exact content requires human approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileWriteInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.WriteFile(ctx, input.HostID, input.Path, input.Content, input.Elevated, input.Reason, input.Rollback, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_stat", Description: "Inspect metadata for one remote file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileListInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.StatFile(ctx, input.HostID, input.Path, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_apply_patch", Description: "Apply an exact unified diff after human approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FilePatchInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ApplyPatch(ctx, input.HostID, input.Cwd, input.Patch, input.Elevated, input.Reason, input.Rollback, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_upload", Description: "Upload a named local artifact through approved SFTP."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.TransferInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.UploadArtifact(ctx, input.HostID, input.ArtifactName, input.RemotePath, input.Reason, input.Rollback, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_download", Description: "Download a remote file into a named local artifact through approved SFTP."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.TransferInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.DownloadArtifact(ctx, input.HostID, input.RemotePath, input.ArtifactName, input.Reason, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ops_artifact_list", Description: "List artifacts available for approved upload or created by approved download."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, agent.ArtifactListOutput, error) {
			items, err := svc.ListArtifacts()
			return nil, agent.ArtifactListOutput{Artifacts: items}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_history_search", Description: "Search previous commands and redacted outputs."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.HistorySearchInput) (*mcp.CallToolResult, agent.HistorySearchOutput, error) {
			runs, err := svc.SearchRuns(ctx, input.Query, input.HostID, input.Limit)
			return nil, agent.HistorySearchOutput{Runs: runs}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_history_get", Description: "Get one audited command with redacted output; raw encrypted output is excluded."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.HistoryGetInput) (*mcp.CallToolResult, service.HistoryResult, error) {
			output, err := svc.GetRun(ctx, input.RunID, false)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_approval_status", Description: "Check a human approval. This tool cannot grant approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ApprovalInput) (*mcp.CallToolResult, agent.ApprovalOutput, error) {
			approval, err := svc.Store().GetApproval(ctx, input.ApprovalID)
			return nil, agent.ApprovalOutput{Approval: approval}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ops_skill_list", Description: "List operational methodology skills. Skills grant no additional SSH privileges."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, agent.SkillListOutput, error) {
			items, err := skills.List()
			return nil, agent.SkillListOutput{Skills: items}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ops_skill_get", Description: "Load a diagnosis, deployment, or recovery skill."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.SkillInput) (*mcp.CallToolResult, skills.Skill, error) {
			item, err := skills.Get(input.Name)
			return nil, item, err
		})
	return &Server{server: server}
}

func (s *Server) Run(ctx context.Context) error {
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

func execRequest(input agent.ExecInput) domain.ExecRequest {
	return domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecProgram, Program: input.Program, Args: input.Args, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}
}

func scriptRequest(input agent.ScriptInput) domain.ExecRequest {
	return domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecScript, Script: input.Script, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}
}
