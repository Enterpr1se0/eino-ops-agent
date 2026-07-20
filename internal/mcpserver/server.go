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
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_exec", Description: "Execute one remote program with separate arguments through deterministic policy, approval, and audit controls. Set background=true for cancellable background execution; it defaults to false."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ExecInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := agent.RunExecutionTool(ctx, svc, execRequest(input), input.Background, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_run_script", Description: "Analyze and run a Bash script. Set background=true for cancellable background execution; it defaults to false. State changes require human approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ScriptInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := agent.RunExecutionTool(ctx, svc, scriptRequest(input), input.Background, "mcp-client")
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_get", Description: "Read a background SSH task's status and bounded redacted stdout and stderr."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.TaskInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			task, result, taskErr, err := svc.GetTask(input.TaskID)
			if task.ID == "" {
				task.ID = input.TaskID
			}
			output, err := agent.TaskToolResult(task, result, taskErr, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_task_cancel", Description: "Cancel a running SSH task."},
		func(_ context.Context, _ *mcp.CallToolRequest, input agent.TaskInput) (*mcp.CallToolResult, map[string]any, error) {
			err := svc.CancelTask(input.TaskID, "mcp-client")
			if err != nil {
				return nil, map[string]any{"tool_version": "1.1", "ok": false, "code": "not_running", "message": err.Error(), "task_id": input.TaskID, "cancelled": false}, nil
			}
			return nil, map[string]any{"tool_version": "1.1", "ok": true, "code": "cancelled", "task_id": input.TaskID, "cancelled": true}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_read", Description: "Read a bounded remote file. Credential paths are denied."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileReadInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ReadFileAdvanced(ctx, input.HostID, input.Path, input.MaxBytes, input.OffsetBytes, input.TailLines, input.Elevated, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_search", Description: "Search bounded literal matches in one remote file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileSearchInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.SearchFile(ctx, input.HostID, input.Path, input.Pattern, input.ContextLines, input.MaxMatches, input.Elevated, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_list", Description: "List a remote directory without changing it."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileListInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ListFiles(ctx, input.HostID, input.Path, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_write", Description: "Request replacement of a remote file. Exact content requires human approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileWriteInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ApplyRemoteConfig(ctx, input.HostID, input.Path, input.Content, "", input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_stat", Description: "Inspect metadata for one remote file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileListInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.StatFile(ctx, input.HostID, input.Path, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_file_apply_patch", Description: "Apply an exact unified diff after human approval."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FilePatchInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ApplyPatchChecked(ctx, input.HostID, input.Cwd, input.Patch, input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_config_apply", Description: "Atomically replace or patch one remote configuration with conflict detection, backup, validation, and rollback."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.ConfigApplyInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ApplyRemoteConfigVersioned(ctx, input.HostID, input.Path, input.Content, input.Patch, input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ssh_config_restore", Description: "Restore the protected backup from an audited configuration operation."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.FileRestoreInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.RestoreRemoteConfig(ctx, input.OperationID, input.Elevated, input.Reason, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_list", Description: "List allowlisted local workspaces without disclosing their host paths."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, agent.WorkspaceListOutput, error) {
			return nil, agent.WorkspaceListOutput{Workspaces: svc.ListWorkspaceCapabilities()}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_file_list", Description: "List a directory inside an allowlisted workspace."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspacePathInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ListWorkspaceFiles(ctx, input.WorkspaceID, input.Path, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_file_read", Description: "Read a bounded workspace file with SHA256 metadata."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspaceReadInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ReadWorkspaceFile(ctx, input.WorkspaceID, input.Path, input.MaxBytes, input.OffsetBytes, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_file_search", Description: "Search literal text in a bounded workspace file."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspaceSearchInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.SearchWorkspace(ctx, input.WorkspaceID, input.Path, input.Pattern, input.MaxMatches, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_file_apply_patch", Description: "Apply an approved, version-bound patch inside a read_write workspace."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspacePatchInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.ApplyWorkspacePatch(ctx, input.WorkspaceID, input.Path, input.Patch, input.ExpectedSHA256, input.Validator, input.Reason, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_file_upload", Description: "Upload one SHA256-bound Workspace file directly to a registered SSH host through approved SFTP."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspaceUploadInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.UploadWorkspaceFileToHost(ctx, input.HostID, input.WorkspaceID, input.Path, input.ExpectedSHA256, input.RemotePath, input.Reason, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "workspace_shell", Description: "Run an approval-gated script through the operator-selected Workspace sandbox or host shell backend."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.WorkspaceShellInput) (*mcp.CallToolResult, domain.ExecResult, error) {
			output, err := svc.RunWorkspaceShell(ctx, input.WorkspaceID, input.Script, input.Cwd, input.Env, input.TimeoutSeconds, input.Reason, input.ExpectedChanges, input.Rollback, "mcp-client")
			output, err = agent.NormalizeExecToolResult(output, err)
			return nil, output, err
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
	mcp.AddTool(server, &mcp.Tool{Name: "ops_skill_list", Description: "List operational methodology skills. Skills grant no additional SSH privileges."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, agent.SkillListOutput, error) {
			items, err := svc.ListEnabledSkills()
			return nil, agent.SkillListOutput{Skills: items}, err
		})
	mcp.AddTool(server, &mcp.Tool{Name: "ops_skill_get", Description: "Load a diagnosis, deployment, or recovery skill."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input agent.SkillInput) (*mcp.CallToolResult, skills.Skill, error) {
			item, err := svc.LoadSkill(ctx, input.Name, "mcp-client")
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
