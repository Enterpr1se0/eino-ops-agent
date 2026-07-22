package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestChatSessionPersistsWorkspaceBinding(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "chat-sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	created, err := st.CreateChatSession(ctx, "session-bound", "project-a")
	if err != nil {
		t.Fatal(err)
	}
	if created.WorkspaceID != "project-a" {
		t.Fatalf("created Workspace = %q", created.WorkspaceID)
	}
	if err := st.AppendChatMessage(ctx, created.ID, "user", "inspect the project"); err != nil {
		t.Fatal(err)
	}
	updated, err := st.SetChatSessionWorkspace(ctx, created.ID, "project-b")
	if err != nil {
		t.Fatal(err)
	}
	if updated.WorkspaceID != "project-b" {
		t.Fatalf("updated Workspace = %q", updated.WorkspaceID)
	}
	sessions, err := st.ListChatSessions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].WorkspaceID != "project-b" || sessions[0].MessageCount != 1 {
		t.Fatalf("sessions = %#v", sessions)
	}
}

func TestChatSessionMigrationBackfillsExistingConversations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-chat.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE chat_messages (
id TEXT PRIMARY KEY, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL);
INSERT INTO chat_messages(id,session_id,role,content,created_at)
VALUES('message-1','legacy-session','user','legacy question','2026-01-01T00:00:00Z')`); err != nil {
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
	session, err := st.GetChatSession(ctx, "legacy-session")
	if err != nil {
		t.Fatal(err)
	}
	if session.WorkspaceID != "" {
		t.Fatalf("legacy conversation unexpectedly bound to %q", session.WorkspaceID)
	}
}
