package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestModelProviderProxyColumnMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy-models.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE model_providers (
id TEXT PRIMARY KEY,
name TEXT NOT NULL UNIQUE,
kind TEXT NOT NULL,
base_url TEXT NOT NULL DEFAULT '',
model TEXT NOT NULL,
api_key_cipher TEXT NOT NULL DEFAULT '',
active INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL,
updated_at TEXT NOT NULL
);
INSERT INTO model_providers(id,name,kind,base_url,model,api_key_cipher,active,created_at,updated_at)
VALUES('legacy','Legacy','openai_compatible','http://127.0.0.1:8080/v1','legacy-model','',0,'now','now');`)
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
	provider, err := st.GetModelProvider(ctx, "legacy")
	if err != nil || provider.ProxyURL != "" || provider.ProxyUsername != "" || provider.HasProxyPassword {
		t.Fatalf("legacy provider did not load with empty proxy settings: provider=%#v err=%v", provider, err)
	}
	rows, err := st.db.QueryContext(ctx, `PRAGMA table_info(model_providers)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		found[name] = true
	}
	for _, column := range []string{"proxy_url", "proxy_username", "proxy_password_cipher"} {
		if !found[column] {
			t.Errorf("migration did not add %s", column)
		}
	}
}
