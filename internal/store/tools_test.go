package store

import (
	"context"
	"testing"
)

func TestAgentToolStatePersists(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/tool-settings.db"
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	states, err := st.AgentToolStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 0 {
		t.Fatalf("new store has unexpected tool settings: %#v", states)
	}
	if err := st.SetAgentToolEnabled(ctx, "ssh_exec", false); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	states, err = reopened.AgentToolStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, configured := states["ssh_exec"]; !configured || enabled {
		t.Fatalf("disabled tool state was not preserved: %#v", states)
	}
	if err := reopened.SetAgentToolEnabled(ctx, "ssh_exec", true); err != nil {
		t.Fatal(err)
	}
	states, err = reopened.AgentToolStates(ctx)
	if err != nil || !states["ssh_exec"] {
		t.Fatalf("enabled tool state was not preserved: states=%#v err=%v", states, err)
	}
}

func TestMigrationRemovesRetiredToolSettings(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/retired-tool-setting.db"
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAgentToolEnabled(ctx, "ssh_approval_status", false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh_task_start", "ssh_task_status", "ssh_task_tail", "ssh_task_list"} {
		if err := st.SetAgentToolEnabled(ctx, name, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SetAgentToolEnabled(ctx, "ssh_exec", false); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	states, err := reopened.AgentToolStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ssh_approval_status", "ssh_task_start", "ssh_task_status", "ssh_task_tail", "ssh_task_list"} {
		if _, exists := states[name]; exists {
			t.Fatalf("retired tool setting %s was not removed: %#v", name, states)
		}
	}
	if enabled, exists := states["ssh_exec"]; !exists || enabled {
		t.Fatalf("migration changed an unrelated tool setting: %#v", states)
	}
}
