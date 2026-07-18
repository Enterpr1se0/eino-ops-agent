package agent

import (
	"context"
	"errors"
	"strings"

	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/skills"
	"eino-ops-agent/internal/store"

	"github.com/cloudwego/eino/components/tool"
	toolutils "github.com/cloudwego/eino/components/tool/utils"
)

type HostInput struct {
	HostID string `json:"host_id" jsonschema:"registered host identifier"`
}

type HostListOutput struct {
	Hosts []domain.HostCapability `json:"hosts"`
}

type ExecInput struct {
	HostID          string            `json:"host_id" jsonschema:"registered host identifier"`
	Program         string            `json:"program" jsonschema:"remote executable; arguments must be separate"`
	Args            []string          `json:"args,omitempty" jsonschema:"argument vector without shell quoting"`
	Cwd             string            `json:"cwd,omitempty" jsonschema:"absolute remote working directory"`
	Env             map[string]string `json:"env,omitempty" jsonschema:"non-secret environment variables"`
	Elevated        bool              `json:"elevated,omitempty" jsonschema:"request root through the host managed sudo policy; never invoke sudo directly or provide a password"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty" jsonschema:"timeout from 1 to 600 seconds"`
	Reason          string            `json:"reason" jsonschema:"specific operational reason supported by evidence"`
	ExpectedChanges string            `json:"expected_changes,omitempty" jsonschema:"state changes expected from this command"`
	Rollback        string            `json:"rollback,omitempty" jsonschema:"how to undo the change"`
}

type ScriptInput struct {
	HostID          string            `json:"host_id" jsonschema:"registered host identifier"`
	Script          string            `json:"script" jsonschema:"complete bash script to analyze and execute"`
	Cwd             string            `json:"cwd,omitempty" jsonschema:"absolute remote working directory"`
	Env             map[string]string `json:"env,omitempty" jsonschema:"non-secret environment variables"`
	Elevated        bool              `json:"elevated,omitempty" jsonschema:"request root through the host managed sudo policy; never put sudo or a password in the script"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty" jsonschema:"timeout from 1 to 600 seconds"`
	Reason          string            `json:"reason" jsonschema:"specific operational reason supported by evidence"`
	ExpectedChanges string            `json:"expected_changes,omitempty" jsonschema:"state changes expected from this script"`
	Rollback        string            `json:"rollback,omitempty" jsonschema:"how to undo the changes"`
}

type FileReadInput struct {
	HostID      string `json:"host_id" jsonschema:"registered host identifier"`
	Path        string `json:"path" jsonschema:"absolute remote file path"`
	MaxBytes    int    `json:"max_bytes,omitempty" jsonschema:"maximum bytes to return, capped by policy"`
	OffsetBytes int64  `json:"offset_bytes,omitempty" jsonschema:"zero-based byte offset; cannot be combined with tail_lines"`
	TailLines   int    `json:"tail_lines,omitempty" jsonschema:"return the last bounded number of lines; cannot be combined with offset_bytes"`
	Elevated    bool   `json:"elevated,omitempty" jsonschema:"read through managed sudo; requires break-glass approval"`
}

type FileListInput struct {
	HostID string `json:"host_id" jsonschema:"registered host identifier"`
	Path   string `json:"path" jsonschema:"absolute remote directory path"`
}

type FileWriteInput struct {
	HostID         string `json:"host_id" jsonschema:"registered host identifier"`
	Path           string `json:"path" jsonschema:"absolute remote file path"`
	Content        string `json:"content" jsonschema:"complete replacement content"`
	Elevated       bool   `json:"elevated,omitempty" jsonschema:"write through the host managed sudo policy; never provide a password"`
	Reason         string `json:"reason" jsonschema:"why the write is needed"`
	Rollback       string `json:"rollback" jsonschema:"how to restore the previous file"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty" jsonschema:"sha256 observed by ssh_file_read; use absent only when creating a new file"`
	Validator      string `json:"validator,omitempty" jsonschema:"optional registered remote validator id"`
}

type FilePatchInput struct {
	HostID         string `json:"host_id" jsonschema:"registered host identifier"`
	Cwd            string `json:"cwd" jsonschema:"absolute directory used as the patch root"`
	Patch          string `json:"patch" jsonschema:"unified diff content"`
	Elevated       bool   `json:"elevated,omitempty" jsonschema:"apply through the host managed sudo policy; never provide a password"`
	Reason         string `json:"reason" jsonschema:"why the patch is needed"`
	Rollback       string `json:"rollback" jsonschema:"how to revert the patch"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty" jsonschema:"sha256 observed for the single target file"`
	Validator      string `json:"validator,omitempty" jsonschema:"optional registered remote validator id"`
}

type FileSearchInput struct {
	HostID       string `json:"host_id" jsonschema:"registered host identifier"`
	Path         string `json:"path" jsonschema:"absolute remote regular file path"`
	Pattern      string `json:"pattern" jsonschema:"literal text to find; not a regular expression"`
	ContextLines int    `json:"context_lines,omitempty" jsonschema:"lines around each match, capped at 10"`
	MaxMatches   int    `json:"max_matches,omitempty" jsonschema:"maximum result lines, capped at 200"`
	Elevated     bool   `json:"elevated,omitempty" jsonschema:"search through managed sudo; requires break-glass approval"`
}

type ConfigApplyInput struct {
	HostID         string `json:"host_id" jsonschema:"registered host identifier"`
	Path           string `json:"path" jsonschema:"single absolute remote configuration file"`
	Content        string `json:"content,omitempty" jsonschema:"complete replacement content; mutually exclusive with patch"`
	Patch          string `json:"patch,omitempty" jsonschema:"unified diff for this one file; mutually exclusive with content"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"sha256 from ssh_file_read, or absent when creating a file"`
	Validator      string `json:"validator,omitempty" jsonschema:"registered remote validator id allowed for this path"`
	Elevated       bool   `json:"elevated,omitempty" jsonschema:"apply through managed sudo; never include sudo or credentials"`
	Reason         string `json:"reason" jsonschema:"evidence-based reason for the exact change"`
	Rollback       string `json:"rollback" jsonschema:"operator-facing rollback intent"`
}

type FileRestoreInput struct {
	OperationID string `json:"operation_id" jsonschema:"audited file operation identifier returned by ssh_config_apply"`
	Reason      string `json:"reason" jsonschema:"why restoration is required"`
	Elevated    bool   `json:"elevated,omitempty" jsonschema:"restore through managed sudo when required"`
}

type WorkspaceListOutput struct {
	Workspaces []service.WorkspaceCapability `json:"workspaces"`
}

type WorkspacePathInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"allowlisted workspace identifier"`
	Path        string `json:"path,omitempty" jsonschema:"clean path relative to the workspace root"`
}

type WorkspaceReadInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"allowlisted workspace identifier"`
	Path        string `json:"path" jsonschema:"clean path relative to the workspace root"`
	MaxBytes    int    `json:"max_bytes,omitempty" jsonschema:"maximum bytes returned, capped by policy"`
	OffsetBytes int64  `json:"offset_bytes,omitempty" jsonschema:"zero-based byte offset"`
}

type WorkspaceSearchInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"allowlisted workspace identifier"`
	Path        string `json:"path" jsonschema:"clean file path relative to the workspace root"`
	Pattern     string `json:"pattern" jsonschema:"literal text to find"`
	MaxMatches  int    `json:"max_matches,omitempty" jsonschema:"maximum matching lines, capped at 200"`
}

type WorkspacePatchInput struct {
	WorkspaceID    string `json:"workspace_id" jsonschema:"allowlisted read_write workspace identifier"`
	Path           string `json:"path" jsonschema:"single clean file path relative to the workspace root"`
	Patch          string `json:"patch" jsonschema:"single-file unified diff"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"sha256 returned by workspace_file_read"`
	Validator      string `json:"validator,omitempty" jsonschema:"allowlisted workspace validator id"`
	Reason         string `json:"reason" jsonschema:"evidence-based reason for the change"`
	Rollback       string `json:"rollback" jsonschema:"how to revert the change"`
}

type WorkspaceUploadInput struct {
	HostID         string `json:"host_id" jsonschema:"registered destination host identifier"`
	WorkspaceID    string `json:"workspace_id" jsonschema:"allowlisted source workspace identifier"`
	Path           string `json:"path" jsonschema:"clean source path relative to the workspace root"`
	ExpectedSHA256 string `json:"expected_sha256" jsonschema:"sha256 returned by workspace_file_read; upload is rejected if the source changed"`
	RemotePath     string `json:"remote_path" jsonschema:"absolute destination path on the remote host"`
	Reason         string `json:"reason" jsonschema:"why this transfer is needed"`
	Rollback       string `json:"rollback" jsonschema:"how to remove or restore the remote destination"`
}

type HistorySearchInput struct {
	Query  string `json:"query,omitempty" jsonschema:"text found in command or redacted output"`
	HostID string `json:"host_id,omitempty" jsonschema:"optional registered host identifier"`
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum 50 results"`
}

type HistorySearchOutput struct {
	Runs []domain.Run `json:"runs"`
}

type HistoryGetInput struct {
	RunID string `json:"run_id" jsonschema:"audit run identifier"`
}

type TaskInput struct {
	TaskID string `json:"task_id" jsonschema:"long-running task identifier"`
}

type TaskOutput struct {
	domain.ToolMeta
	Task   domain.Task       `json:"task"`
	Result domain.ExecResult `json:"result"`
	Error  string            `json:"error,omitempty"`
}

type TaskListOutput struct {
	domain.ToolMeta
	Tasks []domain.Task `json:"tasks"`
}

func NormalizeExecToolResult(result domain.ExecResult, err error) (domain.ExecResult, error) {
	result.ToolVersion = "1.1"
	if err == nil {
		result.OK = result.Status == "completed" || result.Status == "running" || result.Status == "approval_required"
		result.Code = result.Status
		if result.Status == "approval_required" {
			result.NextAction = "wait for the human decision; do not resubmit or try to approve this operation"
		}
		return result, nil
	}
	if errors.Is(err, context.Canceled) {
		return result, err
	}
	result.OK = false
	result.Message = err.Error()
	result.Code, result.Retryable, result.NextAction = classifyToolError(err)
	if result.Status == "" {
		result.Status = "failed"
	}
	return result, nil
}

func TaskToolOutput(task domain.Task, result domain.ExecResult, taskErr string, err error) (TaskOutput, error) {
	output := TaskOutput{Task: task, Result: result, Error: taskErr}
	output.ToolVersion = "1.1"
	if err == nil {
		output.OK = true
		output.Code = task.Status
		return output, nil
	}
	if errors.Is(err, context.Canceled) {
		return output, err
	}
	output.OK = false
	output.Message = err.Error()
	output.Code, output.Retryable, output.NextAction = classifyToolError(err)
	return output, nil
}

func NormalizeTaskStart(task domain.Task, err error) (domain.Task, error) {
	task.ToolVersion = "1.1"
	if err == nil {
		task.OK, task.Code = true, task.Status
		return task, nil
	}
	if errors.Is(err, context.Canceled) {
		return task, err
	}
	task.OK = false
	task.Message = err.Error()
	task.Code, task.Retryable, task.NextAction = classifyToolError(err)
	return task, nil
}

func classifyToolError(err error) (string, bool, string) {
	message := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "not_found", false, "verify the identifier or list available resources; do not retry the same missing identifier"
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(message, "timed out"), strings.Contains(message, "timeout"):
		return "timeout", true, "narrow the operation or use ssh_task_start for a long-running command"
	case strings.Contains(message, "denied"), strings.Contains(message, "forbidden"):
		return "denied", false, "respect the policy decision and choose a safer operation"
	case strings.Contains(message, "required"), strings.Contains(message, "invalid"), strings.Contains(message, "unsupported"):
		return "validation_failed", false, "correct the tool input using the error message; do not repeat unchanged input"
	case strings.Contains(message, "changed"), strings.Contains(message, "conflict"):
		return "conflict", true, "read the current state again before proposing another change"
	default:
		return "remote_failed", true, "inspect stderr and gather narrower read-only evidence before retrying"
	}
}

type ApprovalInput struct {
	ApprovalID string `json:"approval_id" jsonschema:"approval identifier returned by an execution tool"`
}

type ApprovalOutput struct {
	Approval domain.Approval `json:"approval"`
}

type SkillInput struct {
	Name string `json:"name" jsonschema:"skill name returned by ops_skill_list"`
}

type SkillListOutput struct {
	Skills []skills.Skill `json:"skills"`
}

type PlanCreateInput struct {
	Goal  string   `json:"goal" jsonschema:"the user's concrete operational goal"`
	Steps []string `json:"steps" jsonschema:"ordered list of 2 to 8 independently verifiable steps"`
}

type PlanStepUpdateInput struct {
	StepNumber int    `json:"step_number" jsonschema:"the currently in-progress step number"`
	Status     string `json:"status" jsonschema:"completed after verification or blocked when progress genuinely cannot continue"`
	Evidence   string `json:"evidence" jsonschema:"concise observed result or blocker; never claim completion without tool evidence"`
}

type PlanGetOutput struct {
	Found    bool              `json:"found"`
	Plan     *domain.AgentPlan `json:"plan,omitempty"`
	Guidance string            `json:"guidance,omitempty"`
}

func BuildTools(svc *service.Service) ([]tool.BaseTool, error) {
	var tools []tool.BaseTool
	appendTool := func(created tool.InvokableTool, err error) error {
		if err != nil {
			return err
		}
		tools = append(tools, created)
		return nil
	}

	if err := appendTool(toolutils.InferTool("ops_plan_create", "Create or replace the persistent step-by-step plan for a complex task. Provide 2-8 ordered, independently verifiable steps. Step 1 starts automatically and only one step can be in progress.", func(ctx context.Context, input PlanCreateInput) (domain.AgentPlan, error) {
		return svc.CreateAgentPlan(ctx, input.Goal, input.Steps, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ops_plan_get", "Read the persistent plan for the current conversation before resuming a complex task or reporting progress. A conversation without a plan returns found=false; do not retry, and create a plan only when the current request is complex.", func(ctx context.Context, _ struct{}) (PlanGetOutput, error) {
		plan, err := svc.GetAgentPlan(ctx, "")
		if errors.Is(err, store.ErrNotFound) {
			return PlanGetOutput{
				Found:    false,
				Guidance: "This conversation has no persistent plan. Do not retry ops_plan_get. Create one only if the current request is a complex operational task; otherwise continue without a plan.",
			}, nil
		}
		if err != nil {
			return PlanGetOutput{}, err
		}
		return PlanGetOutput{Found: true, Plan: &plan}, nil
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ops_plan_step_update", "Finish the current plan step with observed evidence, or mark it blocked with the exact blocker. A completed step automatically starts the next pending step; steps cannot be skipped or completed out of order.", func(ctx context.Context, input PlanStepUpdateInput) (domain.AgentPlan, error) {
		return svc.UpdateAgentPlanStep(ctx, input.StepNumber, input.Status, input.Evidence, "eino-agent")
	})); err != nil {
		return nil, err
	}

	if err := appendTool(toolutils.InferTool("ssh_host_inspect", "Inspect a registered SSH host and return hostname, kernel, architecture, user, and uptime. This is read-only.", func(ctx context.Context, input HostInput) (any, error) {
		return svc.ProbeHost(ctx, input.HostID)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_host_list", "List registered host IDs, display names, authentication types, and managed sudo modes. Connection details and credentials are excluded.", func(ctx context.Context, _ struct{}) (HostListOutput, error) {
		hosts, err := svc.ListHostCapabilities(ctx)
		return HostListOutput{Hosts: hosts}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_exec", "Execute one remote program with a separate argument vector. Set elevated=true when root is required; credentials are injected by the control plane and all elevated requests require break-glass approval.", func(ctx context.Context, input ExecInput) (domain.ExecResult, error) {
		result, err := svc.Submit(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecProgram, Program: input.Program, Args: input.Args, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_run_script", "Run a complete Bash script after deterministic AST risk analysis. Set elevated=true for control-plane-managed sudo; never embed sudo or credentials in the script.", func(ctx context.Context, input ScriptInput) (domain.ExecResult, error) {
		result, err := svc.Submit(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecScript, Script: input.Script, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_start", "Start a long-running remote command as a cancellable task. The same policy and approval controls apply.", func(ctx context.Context, input ExecInput) (domain.Task, error) {
		task, err := svc.StartTask(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecProgram, Program: input.Program, Args: input.Args, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
		return NormalizeTaskStart(task, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_status", "Get status and bounded output for a long-running SSH task.", func(_ context.Context, input TaskInput) (TaskOutput, error) {
		task, result, taskErr, err := svc.GetTask(input.TaskID)
		return TaskToolOutput(task, result, taskErr, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_tail", "Read the latest bounded, redacted stdout and stderr accumulated by a running SSH task.", func(_ context.Context, input TaskInput) (TaskOutput, error) {
		task, result, taskErr, err := svc.GetTask(input.TaskID)
		return TaskToolOutput(task, result, taskErr, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_cancel", "Cancel a long-running SSH task.", func(_ context.Context, input TaskInput) (map[string]any, error) {
		err := svc.CancelTask(input.TaskID, "eino-agent")
		if err == nil {
			return map[string]any{"tool_version": "1.1", "ok": true, "code": "cancelled", "task_id": input.TaskID, "cancelled": true}, nil
		}
		code, retryable, nextAction := classifyToolError(err)
		return map[string]any{"tool_version": "1.1", "ok": false, "code": code, "message": err.Error(), "retryable": retryable, "next_action": nextAction, "task_id": input.TaskID, "cancelled": false}, nil
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_list", "List persisted recent SSH tasks, including tasks marked interrupted after a control-plane restart.", func(ctx context.Context, _ struct{}) (TaskListOutput, error) {
		tasks, err := svc.ListTasks(ctx, 50)
		output := TaskListOutput{Tasks: tasks}
		output.ToolVersion = "1.1"
		if err != nil {
			output.Code, output.Retryable, output.NextAction = classifyToolError(err)
			output.Message = err.Error()
			return output, nil
		}
		output.OK, output.Code = true, "completed"
		return output, nil
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_read", "Read at most a bounded number of bytes from a remote file. Sensitive credential paths are denied.", func(ctx context.Context, input FileReadInput) (domain.ExecResult, error) {
		result, err := svc.ReadFileAdvanced(ctx, input.HostID, input.Path, input.MaxBytes, input.OffsetBytes, input.TailLines, input.Elevated, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_search", "Search literal text in one remote file and return bounded matching lines with context. Sensitive paths are denied.", func(ctx context.Context, input FileSearchInput) (domain.ExecResult, error) {
		result, err := svc.SearchFile(ctx, input.HostID, input.Path, input.Pattern, input.ContextLines, input.MaxMatches, input.Elevated, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_list", "List a remote directory without changing it.", func(ctx context.Context, input FileListInput) (domain.ExecResult, error) {
		result, err := svc.ListFiles(ctx, input.HostID, input.Path, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_write", "Replace a remote file. The write is never performed until a human approves the exact content digest.", func(ctx context.Context, input FileWriteInput) (domain.ExecResult, error) {
		result, err := svc.ApplyRemoteConfig(ctx, input.HostID, input.Path, input.Content, "", input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_stat", "Inspect metadata for one absolute remote file path.", func(ctx context.Context, input FileListInput) (domain.ExecResult, error) {
		result, err := svc.StatFile(ctx, input.HostID, input.Path, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_apply_patch", "Apply a unified diff in a remote directory after human approval of the exact patch digest.", func(ctx context.Context, input FilePatchInput) (domain.ExecResult, error) {
		result, err := svc.ApplyPatchChecked(ctx, input.HostID, input.Cwd, input.Patch, input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_config_apply", "Atomically replace or patch one remote configuration file with SHA256 conflict detection, protected backup, optional allowlisted validation, and automatic rollback.", func(ctx context.Context, input ConfigApplyInput) (domain.ExecResult, error) {
		result, err := svc.ApplyRemoteConfigVersioned(ctx, input.HostID, input.Path, input.Content, input.Patch, input.ExpectedSHA256, input.Validator, input.Elevated, input.Reason, input.Rollback, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_config_restore", "Restore the protected backup recorded by one audited ssh_config_apply operation. Human approval is always required.", func(ctx context.Context, input FileRestoreInput) (domain.ExecResult, error) {
		result, err := svc.RestoreRemoteConfig(ctx, input.OperationID, input.Elevated, input.Reason, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_list", "List administrator-allowlisted local project workspaces and their read_only or read_write capability. Root paths are never disclosed.", func(_ context.Context, _ struct{}) (WorkspaceListOutput, error) {
		return WorkspaceListOutput{Workspaces: svc.ListWorkspaceCapabilities()}, nil
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_file_list", "List one directory inside an allowlisted workspace. Symbolic links and sensitive control-plane paths are excluded.", func(ctx context.Context, input WorkspacePathInput) (domain.ExecResult, error) {
		result, err := svc.ListWorkspaceFiles(ctx, input.WorkspaceID, input.Path, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_file_read", "Read a bounded file from an allowlisted workspace with SHA256 metadata. Sensitive paths are denied.", func(ctx context.Context, input WorkspaceReadInput) (domain.ExecResult, error) {
		result, err := svc.ReadWorkspaceFile(ctx, input.WorkspaceID, input.Path, input.MaxBytes, input.OffsetBytes, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_file_search", "Search bounded literal matches in a single allowlisted workspace file.", func(ctx context.Context, input WorkspaceSearchInput) (domain.ExecResult, error) {
		result, err := svc.SearchWorkspace(ctx, input.WorkspaceID, input.Path, input.Pattern, input.MaxMatches, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_file_apply_patch", "Apply a single-file unified diff inside a read_write workspace with SHA256 conflict detection, approval, atomic replacement, optional validation, backup, and rollback on failure.", func(ctx context.Context, input WorkspacePatchInput) (domain.ExecResult, error) {
		result, err := svc.ApplyWorkspacePatch(ctx, input.WorkspaceID, input.Path, input.Patch, input.ExpectedSHA256, input.Validator, input.Reason, input.Rollback, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("workspace_file_upload", "Upload one Workspace file to a registered SSH host through one approved SFTP operation. Always bind expected_sha256 from workspace_file_read. This is the only supported local-to-remote file transfer path.", func(ctx context.Context, input WorkspaceUploadInput) (domain.ExecResult, error) {
		result, err := svc.UploadWorkspaceFileToHost(ctx, input.HostID, input.WorkspaceID, input.Path, input.ExpectedSHA256, input.RemotePath, input.Reason, input.Rollback, "eino-agent")
		return NormalizeExecToolResult(result, err)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_history_search", "Search prior commands and redacted results to reuse evidence and avoid repeating failed operations.", func(ctx context.Context, input HistorySearchInput) (HistorySearchOutput, error) {
		runs, err := svc.SearchRuns(ctx, input.Query, input.HostID, input.Limit)
		return HistorySearchOutput{Runs: runs}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_history_get", "Get one audited command and its redacted result. Raw encrypted output is never exposed to the model.", func(ctx context.Context, input HistoryGetInput) (service.HistoryResult, error) {
		return svc.GetRun(ctx, input.RunID, false)
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_approval_status", "Check whether a human has approved or rejected a pending SSH operation. This tool cannot approve operations.", func(ctx context.Context, input ApprovalInput) (ApprovalOutput, error) {
		approval, err := svc.Store().GetApproval(ctx, input.ApprovalID)
		return ApprovalOutput{Approval: approval}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ops_skill_list", "List built-in operational skills for diagnosis, deployment, and recovery. Skills provide methodology but no extra permissions.", func(_ context.Context, _ struct{}) (SkillListOutput, error) {
		items, err := skills.List()
		return SkillListOutput{Skills: items}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ops_skill_get", "Load one built-in operational skill before handling a matching complex workflow.", func(_ context.Context, input SkillInput) (skills.Skill, error) {
		return skills.Get(input.Name)
	})); err != nil {
		return nil, err
	}
	return tools, nil
}
