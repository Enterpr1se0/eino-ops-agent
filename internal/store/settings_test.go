package store

import (
	"context"
	"database/sql"
	"testing"

	"eino-ops-agent/internal/domain"
)

func TestLegacyReviewSettingsMigrateToOneExplanationToggle(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/legacy-settings.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE system_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  agent_max_iterations INTEGER NOT NULL,
  subagent_reviews_enabled INTEGER NOT NULL DEFAULT 1,
  beginner_explanations_enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO system_settings(id,agent_max_iterations,subagent_reviews_enabled,beginner_explanations_enabled,updated_at)
VALUES(1,20,1,0,'2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := st.GetSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ApprovalExplanationsEnabled {
		t.Fatalf("legacy disabled explanation was not preserved: %#v", settings)
	}
	settings.ApprovalExplanationsEnabled = true
	if _, err := st.SaveSystemSettings(ctx, settings); err != nil {
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
	settings, err = reopened.GetSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ApprovalExplanationsEnabled || settings.AgentMaxIterations != domain.DefaultAgentMaxIterations {
		// The stored iteration value is 20, which is also the current default;
		// checking both guards the legacy row and the new toggle on reopen.
		t.Fatalf("migrated explanation setting did not persist: %#v", settings)
	}
}
