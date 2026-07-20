package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/policy"
	"eino-ops-agent/internal/security"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/sshx"
	"eino-ops-agent/internal/store"

	"github.com/cloudwego/eino/components/tool"
)

type backgroundToolTransport struct {
	started chan domain.ExecRequest
	release chan struct{}
}

func (t *backgroundToolTransport) Exec(ctx context.Context, _ sshx.ConnectionSpec, request domain.ExecRequest) (sshx.RawResult, error) {
	t.started <- request
	select {
	case <-t.release:
		return sshx.RawResult{Stdout: []byte("background complete\n")}, nil
	case <-ctx.Done():
		return sshx.RawResult{}, ctx.Err()
	}
}

func (*backgroundToolTransport) Probe(context.Context, sshx.ConnectionSpec) (sshx.HostInfo, error) {
	return sshx.HostInfo{}, nil
}

func (*backgroundToolTransport) ScanHostKey(context.Context, sshx.ConnectionSpec) (sshx.HostKey, error) {
	return sshx.HostKey{}, nil
}

func (*backgroundToolTransport) TrustHostKey(context.Context, sshx.ConnectionSpec, string) (sshx.HostKey, error) {
	return sshx.HostKey{}, nil
}

func TestToolDescriptorsMatchTheEinoSchemasLoadedByTheAgent(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/catalog.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, engine, nil, encryptor, security.NewRedactor(), config.Default().Limits)
	loaded, err := BuildTools(svc)
	if err != nil {
		t.Fatal(err)
	}
	descriptors, err := DescribeTools(ctx, loaded)
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != len(loaded) || len(descriptors) < 20 {
		t.Fatalf("catalog=%d loaded=%d", len(descriptors), len(loaded))
	}
	if len(descriptors) != 30 {
		t.Fatalf("built-in catalog size=%d, want 30", len(descriptors))
	}

	seen := make(map[string]bool, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Name == "" || descriptor.Description == "" || descriptor.Category == "" || descriptor.Guard == "" {
			t.Fatalf("incomplete descriptor: %#v", descriptor)
		}
		if seen[descriptor.Name] {
			t.Fatalf("duplicate function %q", descriptor.Name)
		}
		seen[descriptor.Name] = true
		if !json.Valid(descriptor.InputSchema) {
			t.Fatalf("invalid schema for %s: %s", descriptor.Name, descriptor.InputSchema)
		}
		if descriptor.Name == "ssh_exec" {
			if descriptor.Guard != "policy_checked" || !strings.Contains(string(descriptor.InputSchema), `"host_id"`) || !strings.Contains(string(descriptor.InputSchema), `"program"`) || !strings.Contains(string(descriptor.InputSchema), `"background"`) {
				t.Fatalf("ssh_exec metadata does not reflect its runtime schema: %#v", descriptor)
			}
			var schema struct {
				Required []string `json:"required"`
			}
			if err := json.Unmarshal(descriptor.InputSchema, &schema); err != nil {
				t.Fatal(err)
			}
			for _, required := range schema.Required {
				if required == "background" {
					t.Fatal("ssh_exec background must remain optional and default to false")
				}
			}
		}
		if descriptor.Name == "ssh_run_script" && !strings.Contains(string(descriptor.InputSchema), `"background"`) {
			t.Fatalf("ssh_run_script metadata is missing background: %#v", descriptor)
		}
		if descriptor.Name == "workspace_shell" && descriptor.Guard != "approval_required" {
			t.Fatalf("workspace_shell must be approval-gated: %#v", descriptor)
		}
		if descriptor.Name == "web_extract" && (descriptor.Guard != "read_only" || descriptor.Category != "web" || !strings.Contains(string(descriptor.InputSchema), `"urls"`)) {
			t.Fatalf("web_extract metadata does not reflect its runtime schema: %#v", descriptor)
		}
	}
	for _, retired := range []string{"ssh_approval_status", "ssh_task_start", "ssh_task_status", "ssh_task_tail", "ssh_task_list"} {
		if seen[retired] {
			t.Fatalf("removed %s tool remains in the Agent catalog", retired)
		}
	}
	if !seen["ops_plan_get"] || !seen["ssh_config_apply"] || !seen["workspace_file_upload"] || !seen["workspace_shell"] || !seen["web_search"] || !seen["web_extract"] || !seen["ssh_task_get"] || !seen["ssh_task_cancel"] {
		t.Fatalf("representative functions missing: %#v", seen)
	}
}

func TestWebExtractToolResultExposesPartialAndProviderFailures(t *testing.T) {
	partial, err := NormalizeWebExtractToolResult(domain.WebExtractResponse{
		Results:       []domain.WebExtractResult{{URL: "https://example.com", RawContent: "ok"}},
		FailedResults: []domain.WebExtractFailedResult{{URL: "https://example.org", Error: "failed"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !partial.OK || partial.Code != "partial" || len(partial.FailedResults) != 1 || !partial.ContentIsUntrusted {
		t.Fatalf("partial extraction was not exposed to the model: %#v", partial)
	}
	failed, err := NormalizeWebExtractToolResult(domain.WebExtractResponse{
		FailedResults: []domain.WebExtractFailedResult{{URL: "https://example.org", Error: "blocked"}},
	}, service.ErrWebSearchUpstream)
	if err != nil {
		t.Fatal(err)
	}
	if failed.OK || failed.Code != "provider_failed" || !failed.Retryable || len(failed.FailedResults) != 1 {
		t.Fatalf("provider extraction failure was not exposed to the model: %#v", failed)
	}
}

func TestTaskToolResultsExposeRejectionAndStderr(t *testing.T) {
	execResult, err := NormalizeExecToolResult(domain.ExecResult{
		RunID:               "run_exec_rejected",
		Status:              "rejected",
		OperatorInstruction: "inspect logs instead",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if execResult.OK || execResult.Code != "rejected" || execResult.OperatorInstruction == "" || !strings.Contains(execResult.NextAction, "do not resubmit") {
		t.Fatalf("rejected execution was not exposed as an operator interruption: %#v", execResult)
	}

	task := domain.Task{
		ID:                  "task_rejected",
		RunID:               "run_rejected",
		Status:              "rejected",
		OperatorInstruction: "stop the test and only summarize existing evidence",
	}
	status, err := TaskToolResult(task, domain.ExecResult{Status: "rejected", OperatorInstruction: task.OperatorInstruction}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.OK || status.TaskID != task.ID || status.OperatorInstruction != task.OperatorInstruction || !strings.Contains(status.NextAction, "do not resubmit") {
		t.Fatalf("task status lost the operator interruption: %#v", status)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"operator_instruction":"stop the test and only summarize existing evidence"`) {
		t.Fatalf("serialized Tool result lost the operator instruction: %s", encoded)
	}

	failed, err := TaskToolResult(
		domain.Task{ID: "task_failed", RunID: "run_failed", Status: "failed"},
		domain.ExecResult{RunID: "run_failed", Status: "failed", ExitCode: 1, Stderr: "sleep: missing operand"},
		"", nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if failed.OK || failed.Code != "failed" || !strings.Contains(string(encoded), `"stderr":"sleep: missing operand"`) || !strings.Contains(failed.NextAction, "stderr") {
		t.Fatalf("failed task did not expose stderr to the model: output=%#v json=%s", failed, encoded)
	}
}

func TestRunScriptBackgroundReturnsTaskAndTaskGetReturnsOutput(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/background-tools.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, _ := policy.Load("")
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transport := &backgroundToolTransport{started: make(chan domain.ExecRequest, 1), release: make(chan struct{})}
	defer func() {
		select {
		case <-transport.release:
		default:
			close(transport.release)
		}
	}()
	svc := service.New(st, engine, transport, encryptor, security.NewRedactor(), config.Default().Limits)
	host, err := svc.AddHost(ctx, domain.Host{Name: "background-host", Address: "127.0.0.1", Port: 22, User: "ops"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := BuildTools(svc)
	if err != nil {
		t.Fatal(err)
	}
	var scriptTool, getTool tool.InvokableTool
	for _, candidate := range loaded {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		switch info.Name {
		case "ssh_run_script":
			scriptTool = candidate.(tool.InvokableTool)
		case "ssh_task_get":
			getTool = candidate.(tool.InvokableTool)
		}
	}
	if scriptTool == nil || getTool == nil {
		t.Fatal("merged background tools are missing")
	}
	inputJSON, _ := json.Marshal(map[string]any{
		"host_id": host.ID, "script": "printf 'background complete\\n'", "background": true, "reason": "verify background script execution",
	})
	startedJSON, err := scriptTool.InvokableRun(ctx, string(inputJSON))
	if err != nil {
		t.Fatal(err)
	}
	var started domain.ExecResult
	if err := json.Unmarshal([]byte(startedJSON), &started); err != nil {
		t.Fatal(err)
	}
	if !started.OK || started.Status != "running" || started.TaskID == "" {
		t.Fatalf("background script did not return a running task: %#v", started)
	}
	select {
	case request := <-transport.started:
		if request.Mode != domain.ExecScript || request.Script == "" {
			t.Fatalf("background request lost script mode: %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("background script did not reach the SSH transport")
	}
	close(transport.release)

	getInput, _ := json.Marshal(map[string]string{"task_id": started.TaskID})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resultJSON, getErr := getTool.InvokableRun(ctx, string(getInput))
		if getErr != nil {
			t.Fatal(getErr)
		}
		var result domain.ExecResult
		if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
			t.Fatal(err)
		}
		if result.Status == "completed" {
			if !result.OK || result.TaskID != started.TaskID || result.Stdout != "background complete\n" {
				t.Fatalf("unexpected completed task result: %#v", result)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("background task did not complete")
}

func TestDisabledToolIsExcludedFromRunnerAndRetainedInCatalog(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/disabled-tools.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, engine, nil, encryptor, security.NewRedactor(), config.Default().Limits)
	if err := svc.SetAgentToolEnabled(ctx, "ssh_exec", false, "test"); err != nil {
		t.Fatal(err)
	}

	loaded, catalog, err := buildToolSet(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	loadedNames := make(map[string]bool, len(loaded))
	for _, candidate := range loaded {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		loadedNames[info.Name] = true
	}
	if loadedNames["ssh_exec"] {
		t.Fatal("disabled ssh_exec was still loaded into the runner")
	}
	foundDisabled := false
	for _, descriptor := range catalog {
		if descriptor.Name == "ssh_exec" {
			foundDisabled = true
			if descriptor.Enabled {
				t.Fatal("disabled ssh_exec was marked enabled in the catalog")
			}
		}
	}
	if !foundDisabled {
		t.Fatal("disabled ssh_exec disappeared from the management catalog")
	}

	if err := svc.SetAgentToolEnabled(ctx, "ssh_exec", true, "test"); err != nil {
		t.Fatal(err)
	}
	reloaded, _, err := buildToolSet(ctx, svc)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range reloaded {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "ssh_exec" {
			return
		}
	}
	t.Fatal("re-enabled ssh_exec was not loaded into the runner")
}

func TestSkillToolsReadTheLiveAdministratorRegistry(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/skills.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, _ := policy.Load("")
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	svc := service.New(st, engine, nil, encryptor, security.NewRedactor(), cfg.Limits, cfg)
	if _, err := svc.SaveAdminSkill(ctx, "custom-diagnosis", "# Custom Diagnosis\n\nUse the administrator workflow.", "test"); err != nil {
		t.Fatal(err)
	}
	loaded, err := BuildTools(svc)
	if err != nil {
		t.Fatal(err)
	}
	var getTool, listTool tool.InvokableTool
	for _, candidate := range loaded {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "ops_skill_get" {
			getTool = candidate.(tool.InvokableTool)
		}
		if info.Name == "ops_skill_list" {
			listTool = candidate.(tool.InvokableTool)
		}
	}
	if getTool == nil {
		t.Fatal("ops_skill_get was not registered")
	}
	result, err := getTool.InvokableRun(service.WithSessionID(ctx, "session_skill"), `{"name":"custom-diagnosis"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "Use the administrator workflow") {
		t.Fatalf("dynamic skill content was not returned: %s", result)
	}
	if _, err := svc.SetAdminSkillEnabled(ctx, "custom-diagnosis", false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := getTool.InvokableRun(ctx, `{"name":"custom-diagnosis"}`); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("disabled skill remained loadable: %v", err)
	}
	listed, err := listTool.InvokableRun(ctx, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(listed, "custom-diagnosis") {
		t.Fatalf("disabled skill remained discoverable: %s", listed)
	}
}

func TestPlanGetToolTreatsMissingPlanAsRecoverableState(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/tools.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, err := policy.Load("")
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, engine, nil, encryptor, security.NewRedactor(), config.Default().Limits)
	tools, err := BuildTools(svc)
	if err != nil {
		t.Fatal(err)
	}
	var planTool tool.InvokableTool
	for _, candidate := range tools {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "ops_plan_get" {
			planTool = candidate.(tool.InvokableTool)
			break
		}
	}
	if planTool == nil {
		t.Fatal("ops_plan_get tool was not registered")
	}

	sessionCtx := service.WithSessionID(ctx, "session_without_plan")
	resultJSON, err := planTool.InvokableRun(sessionCtx, `{}`)
	if err != nil {
		t.Fatalf("a missing optional plan aborted the ToolNode: %v", err)
	}
	var missing PlanGetOutput
	if err := json.Unmarshal([]byte(resultJSON), &missing); err != nil {
		t.Fatal(err)
	}
	if missing.Found || missing.Plan != nil || missing.Guidance == "" {
		t.Fatalf("unexpected missing-plan result: %#v", missing)
	}

	created, err := svc.CreateAgentPlan(sessionCtx, "Diagnose the service", []string{"Collect evidence", "Verify the cause"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	resultJSON, err = planTool.InvokableRun(sessionCtx, `{}`)
	if err != nil {
		t.Fatal(err)
	}
	var found PlanGetOutput
	if err := json.Unmarshal([]byte(resultJSON), &found); err != nil {
		t.Fatal(err)
	}
	if !found.Found || found.Plan == nil || found.Plan.SessionID != created.SessionID || len(found.Plan.Steps) != 2 {
		t.Fatalf("existing plan was not returned: %#v", found)
	}
}

func TestExecutionToolReturnsStructuredNotFoundWithoutAbortingToolNode(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir()+"/tools.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	engine, _ := policy.Load("")
	encryptor, err := security.NewEncryptor("", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(st, engine, nil, encryptor, security.NewRedactor(), config.Default().Limits)
	tools, err := BuildTools(svc)
	if err != nil {
		t.Fatal(err)
	}
	var execTool tool.InvokableTool
	for _, candidate := range tools {
		info, infoErr := candidate.Info(ctx)
		if infoErr != nil {
			t.Fatal(infoErr)
		}
		if info.Name == "ssh_exec" {
			execTool = candidate.(tool.InvokableTool)
		}
	}
	resultJSON, err := execTool.InvokableRun(ctx, `{"host_id":"missing","program":"id","reason":"inspect identity"}`)
	if err != nil {
		t.Fatalf("expected not_found Tool result, got fatal error: %v", err)
	}
	var result domain.ExecResult
	if err := json.Unmarshal([]byte(resultJSON), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || result.Code != "not_found" || result.Retryable || result.TaskID != "" {
		t.Fatalf("unexpected structured failure: %#v", result)
	}
}
