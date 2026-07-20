package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"eino-ops-agent/internal/domain"
)

func TestWorkspaceConfigurationSeedsOnlyOnceAndPersists(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workspaces.db")
	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeWorkspaces(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListWorkspaces(ctx)
	if err != nil || len(items) != 1 || items[0].ID != "default" {
		t.Fatalf("configured workspace was not seeded: %#v err=%v", items, err)
	}
	if err := st.DeleteWorkspace(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if err := st.InitializeWorkspaces(ctx); err != nil {
		t.Fatal(err)
	}
	items, err = st.ListWorkspaces(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("removed configured workspace was seeded again: %#v err=%v", items, err)
	}
	now := time.Now().UTC()
	dynamic := domain.Workspace{ID: "dynamic", Access: "read_only", CreatedAt: now, UpdatedAt: now}
	if err := st.CreateWorkspace(ctx, dynamic); err != nil {
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
	items, err = reopened.ListWorkspaces(ctx)
	if err != nil || len(items) != 1 || items[0].ID != "dynamic" || items[0].Access != "read_only" {
		t.Fatalf("dynamic workspace did not persist: %#v err=%v", items, err)
	}
}

func TestWorkspaceRootColumnMigrationResetsRegistrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE workspaces (
id TEXT PRIMARY KEY, root TEXT NOT NULL UNIQUE, access TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE workspace_state (id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL DEFAULT 0);
INSERT INTO workspaces VALUES ('legacy','/tmp/legacy','read_only','now','now');
INSERT INTO workspace_state VALUES (1,1);`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.InitializeWorkspaces(ctx); err != nil {
		t.Fatal(err)
	}
	items, err := st.ListWorkspaces(ctx)
	if err != nil || len(items) != 1 || items[0].ID != "default" || items[0].Access != "read_write" {
		t.Fatalf("legacy registrations were not reset: %#v err=%v", items, err)
	}
	rows, err := st.db.QueryContext(ctx, `PRAGMA table_info(workspaces)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if name == "root" {
			t.Fatal("legacy root column still exists")
		}
	}
}
