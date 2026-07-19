package store

import (
	"context"
	"database/sql"
	"testing"

	"eino-ops-agent/internal/domain"
)

func TestLegacySystemSSHHostsAreRemovedAndSchemaIsSimplified(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/legacy-hosts.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
	username TEXT NOT NULL,
	transport_backend TEXT NOT NULL DEFAULT 'system',
	auth_type TEXT NOT NULL DEFAULT 'agent',
  config_alias TEXT NOT NULL DEFAULT '',
  identity_file TEXT NOT NULL DEFAULT '',
  known_hosts_file TEXT NOT NULL DEFAULT '',
  proxy_jump TEXT NOT NULL DEFAULT '',
  password_cipher TEXT NOT NULL DEFAULT '',
  sudo_mode TEXT NOT NULL DEFAULT 'none',
  sudo_password_cipher TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO hosts(id,name,address,port,username,auth_type,identity_file,created_at,updated_at)
VALUES('legacy-host','legacy','192.0.2.10',22,'ops','key','/legacy/id_ed25519','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`)
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
	if _, err := st.GetHost(ctx, "legacy-host"); err != ErrNotFound {
		t.Fatalf("legacy System SSH host survived breaking migration: %v", err)
	}
	rows, err := st.db.QueryContext(ctx, `PRAGMA table_info(hosts)`)
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
		switch name {
		case "transport_backend", "config_alias", "proxy_jump", "identity_file":
			t.Fatalf("obsolete System SSH column %q survived migration", name)
		}
	}
	created, err := st.UpsertHost(ctx, domain.Host{Name: "native", Address: "192.0.2.11", Port: 22, User: "ops", AuthType: "agent", SudoMode: "none"})
	if err != nil || created.Name != "native" {
		t.Fatalf("Native SSH host did not persist after migration: host=%#v err=%v", created, err)
	}
}
