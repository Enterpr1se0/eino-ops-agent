package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"eino-ops-agent/internal/config"
	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/policy"
	"eino-ops-agent/internal/security"
	"eino-ops-agent/internal/service"
	"eino-ops-agent/internal/store"

	"github.com/cloudwego/eino/components/tool"
)

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
			if descriptor.Guard != "policy_checked" || !strings.Contains(string(descriptor.InputSchema), `"host_id"`) || !strings.Contains(string(descriptor.InputSchema), `"program"`) {
				t.Fatalf("ssh_exec metadata does not reflect its runtime schema: %#v", descriptor)
			}
		}
	}
	if !seen["ops_plan_get"] || !seen["ssh_config_apply"] || !seen["workspace_file_upload"] {
		t.Fatalf("representative functions missing: %#v", seen)
	}
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
	if result.OK || result.Code != "not_found" || result.Retryable {
		t.Fatalf("unexpected structured failure: %#v", result)
	}
}
