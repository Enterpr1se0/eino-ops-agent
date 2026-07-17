package agent

import (
	"context"

	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/skills"

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
	HostID   string `json:"host_id" jsonschema:"registered host identifier"`
	Path     string `json:"path" jsonschema:"absolute remote file path"`
	MaxBytes int    `json:"max_bytes,omitempty" jsonschema:"maximum bytes to return, capped by policy"`
}

type FileListInput struct {
	HostID string `json:"host_id" jsonschema:"registered host identifier"`
	Path   string `json:"path" jsonschema:"absolute remote directory path"`
}

type FileWriteInput struct {
	HostID   string `json:"host_id" jsonschema:"registered host identifier"`
	Path     string `json:"path" jsonschema:"absolute remote file path"`
	Content  string `json:"content" jsonschema:"complete replacement content"`
	Elevated bool   `json:"elevated,omitempty" jsonschema:"write through the host managed sudo policy; never provide a password"`
	Reason   string `json:"reason" jsonschema:"why the write is needed"`
	Rollback string `json:"rollback" jsonschema:"how to restore the previous file"`
}

type FilePatchInput struct {
	HostID   string `json:"host_id" jsonschema:"registered host identifier"`
	Cwd      string `json:"cwd" jsonschema:"absolute directory used as the patch root"`
	Patch    string `json:"patch" jsonschema:"unified diff content"`
	Elevated bool   `json:"elevated,omitempty" jsonschema:"apply through the host managed sudo policy; never provide a password"`
	Reason   string `json:"reason" jsonschema:"why the patch is needed"`
	Rollback string `json:"rollback" jsonschema:"how to revert the patch"`
}

type TransferInput struct {
	HostID       string `json:"host_id" jsonschema:"registered host identifier"`
	ArtifactName string `json:"artifact_name" jsonschema:"artifact managed by the local control plane"`
	RemotePath   string `json:"remote_path" jsonschema:"absolute remote file path"`
	Reason       string `json:"reason" jsonschema:"why the transfer is needed"`
	Rollback     string `json:"rollback,omitempty" jsonschema:"how to undo an upload"`
}

type ArtifactListOutput struct {
	Artifacts []domain.Artifact `json:"artifacts"`
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
	Task   domain.Task       `json:"task"`
	Result domain.ExecResult `json:"result"`
	Error  string            `json:"error,omitempty"`
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
	if err := appendTool(toolutils.InferTool("ops_plan_get", "Read the persistent plan for the current conversation before resuming a complex task or reporting progress.", func(ctx context.Context, _ struct{}) (domain.AgentPlan, error) {
		return svc.GetAgentPlan(ctx, "")
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
		return svc.Submit(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecProgram, Program: input.Program, Args: input.Args, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_run_script", "Run a complete Bash script after deterministic AST risk analysis. Set elevated=true for control-plane-managed sudo; never embed sudo or credentials in the script.", func(ctx context.Context, input ScriptInput) (domain.ExecResult, error) {
		return svc.Submit(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecScript, Script: input.Script, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_start", "Start a long-running remote command as a cancellable task. The same policy and approval controls apply.", func(ctx context.Context, input ExecInput) (domain.Task, error) {
		return svc.StartTask(ctx, domain.ExecRequest{HostID: input.HostID, Mode: domain.ExecProgram, Program: input.Program, Args: input.Args, Cwd: input.Cwd, Env: input.Env, Elevated: input.Elevated, TimeoutSeconds: input.TimeoutSeconds, Reason: input.Reason, ExpectedChanges: input.ExpectedChanges, Rollback: input.Rollback}, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_status", "Get status and bounded output for a long-running SSH task.", func(_ context.Context, input TaskInput) (TaskOutput, error) {
		task, result, taskErr, err := svc.GetTask(input.TaskID)
		return TaskOutput{Task: task, Result: result, Error: taskErr}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_tail", "Read the latest bounded, redacted stdout and stderr accumulated by a running SSH task.", func(_ context.Context, input TaskInput) (TaskOutput, error) {
		task, result, taskErr, err := svc.GetTask(input.TaskID)
		return TaskOutput{Task: task, Result: result, Error: taskErr}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_task_cancel", "Cancel a long-running SSH task.", func(_ context.Context, input TaskInput) (map[string]any, error) {
		err := svc.CancelTask(input.TaskID, "eino-agent")
		return map[string]any{"task_id": input.TaskID, "cancelled": err == nil}, err
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_read", "Read at most a bounded number of bytes from a remote file. Sensitive credential paths are denied.", func(ctx context.Context, input FileReadInput) (domain.ExecResult, error) {
		return svc.ReadFile(ctx, input.HostID, input.Path, input.MaxBytes, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_list", "List a remote directory without changing it.", func(ctx context.Context, input FileListInput) (domain.ExecResult, error) {
		return svc.ListFiles(ctx, input.HostID, input.Path, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_write", "Replace a remote file. The write is never performed until a human approves the exact content digest.", func(ctx context.Context, input FileWriteInput) (domain.ExecResult, error) {
		return svc.WriteFile(ctx, input.HostID, input.Path, input.Content, input.Elevated, input.Reason, input.Rollback, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_stat", "Inspect metadata for one absolute remote file path.", func(ctx context.Context, input FileListInput) (domain.ExecResult, error) {
		return svc.StatFile(ctx, input.HostID, input.Path, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_apply_patch", "Apply a unified diff in a remote directory after human approval of the exact patch digest.", func(ctx context.Context, input FilePatchInput) (domain.ExecResult, error) {
		return svc.ApplyPatch(ctx, input.HostID, input.Cwd, input.Patch, input.Elevated, input.Reason, input.Rollback, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_upload", "Upload a named local artifact through SFTP. The exact host, artifact and remote path require human approval.", func(ctx context.Context, input TransferInput) (domain.ExecResult, error) {
		return svc.UploadArtifact(ctx, input.HostID, input.ArtifactName, input.RemotePath, input.Reason, input.Rollback, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ssh_file_download", "Download a remote file into a named local artifact through SFTP. Sensitive paths are denied and transfer requires approval.", func(ctx context.Context, input TransferInput) (domain.ExecResult, error) {
		return svc.DownloadArtifact(ctx, input.HostID, input.RemotePath, input.ArtifactName, input.Reason, "eino-agent")
	})); err != nil {
		return nil, err
	}
	if err := appendTool(toolutils.InferTool("ops_artifact_list", "List local artifacts that a human has made available for SSH upload or that were downloaded through an approved operation.", func(_ context.Context, _ struct{}) (ArtifactListOutput, error) {
		items, err := svc.ListArtifacts()
		return ArtifactListOutput{Artifacts: items}, err
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
