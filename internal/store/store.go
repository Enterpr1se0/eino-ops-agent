package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"eino-ops-agent/internal/domain"
	"eino-ops-agent/internal/ids"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

func Open(ctx context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;"); err != nil {
		db.Close()
		return nil, err
	}
	st := &Store{db: db}
	if err := st.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) AdminPasswordHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admin_credentials WHERE id=1`).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return hash, err
}

func (s *Store) SetAdminPasswordHash(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_credentials(id,password_hash,updated_at) VALUES(1,?,?)
ON CONFLICT(id) DO UPDATE SET password_hash=excluded.password_hash,updated_at=excluded.updated_at`, hash, formatTime(time.Now().UTC()))
	return err
}

func (s *Store) CreateWebSession(ctx context.Context, session domain.WebSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions(token_hash,csrf_token,created_at,expires_at) VALUES(?,?,?,?)`,
		session.TokenHash, session.CSRFToken, formatTime(session.CreatedAt), formatTime(session.ExpiresAt))
	return err
}

func (s *Store) GetWebSession(ctx context.Context, tokenHash string) (domain.WebSession, error) {
	var session domain.WebSession
	var created, expires string
	err := s.db.QueryRowContext(ctx, `SELECT token_hash,csrf_token,created_at,expires_at FROM web_sessions WHERE token_hash=?`, tokenHash).Scan(
		&session.TokenHash, &session.CSRFToken, &created, &expires,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WebSession{}, ErrNotFound
	}
	if err != nil {
		return domain.WebSession{}, err
	}
	session.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	session.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = s.DeleteWebSession(ctx, tokenHash)
		return domain.WebSession{}, ErrNotFound
	}
	return session, nil
}

func (s *Store) DeleteWebSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) DeleteAllWebSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions`)
	return err
}

func (s *Store) CreateFileOperation(ctx context.Context, operation domain.FileOperation) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO file_operations(id,run_id,host_id,path,backup_path,before_sha256,after_sha256,validator,status,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`, operation.ID, operation.RunID, operation.HostID, operation.Path, operation.BackupPath,
		operation.BeforeSHA256, operation.AfterSHA256, operation.Validator, operation.Status, formatTime(operation.CreatedAt))
	return err
}

func (s *Store) GetFileOperation(ctx context.Context, id string) (domain.FileOperation, error) {
	var operation domain.FileOperation
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT id,run_id,host_id,path,backup_path,before_sha256,after_sha256,validator,status,created_at FROM file_operations WHERE id=?`, id).Scan(
		&operation.ID, &operation.RunID, &operation.HostID, &operation.Path, &operation.BackupPath, &operation.BeforeSHA256,
		&operation.AfterSHA256, &operation.Validator, &operation.Status, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.FileOperation{}, ErrNotFound
	}
	if err != nil {
		return domain.FileOperation{}, err
	}
	operation.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return operation, nil
}

func (s *Store) UpsertTask(ctx context.Context, task domain.Task, result domain.ExecResult, taskError string) error {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	var ended any
	if !task.EndedAt.IsZero() {
		ended = formatTime(task.EndedAt)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO tasks(id,run_id,host_id,status,result_json,error,started_at,ended_at) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id,status=excluded.status,result_json=excluded.result_json,error=excluded.error,ended_at=excluded.ended_at`,
		task.ID, task.RunID, task.HostID, task.Status, string(resultJSON), taskError, formatTime(task.StartedAt), ended)
	return err
}

func (s *Store) GetTask(ctx context.Context, id string) (domain.Task, domain.ExecResult, string, error) {
	var task domain.Task
	var resultJSON, taskError, started string
	var ended sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,run_id,host_id,status,result_json,error,started_at,ended_at FROM tasks WHERE id=?`, id).Scan(
		&task.ID, &task.RunID, &task.HostID, &task.Status, &resultJSON, &taskError, &started, &ended,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Task{}, domain.ExecResult{}, "", ErrNotFound
	}
	if err != nil {
		return domain.Task{}, domain.ExecResult{}, "", err
	}
	task.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	if ended.Valid {
		task.EndedAt, _ = time.Parse(time.RFC3339Nano, ended.String)
	}
	var result domain.ExecResult
	_ = json.Unmarshal([]byte(resultJSON), &result)
	return task, result, taskError, nil
}

func (s *Store) ListTasks(ctx context.Context, limit int) ([]domain.Task, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,run_id,host_id,status,started_at,ended_at FROM tasks ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Task, 0)
	for rows.Next() {
		var task domain.Task
		var started string
		var ended sql.NullString
		if err := rows.Scan(&task.ID, &task.RunID, &task.HostID, &task.Status, &started, &ended); err != nil {
			return nil, err
		}
		task.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
		if ended.Valid {
			task.EndedAt, _ = time.Parse(time.RFC3339Nano, ended.String)
		}
		result = append(result, task)
	}
	return result, rows.Err()
}

func (s *Store) InterruptActiveTasks(ctx context.Context) error {
	now := formatTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `UPDATE tasks SET status='interrupted',error=CASE WHEN error='' THEN 'control plane restarted before the task completed' ELSE error END,ended_at=? WHERE status IN ('running','waiting_for_approval','approval_required')`, now)
	return err
}

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS hosts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  address TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL,
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
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL DEFAULT '',
  host_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  request_cipher TEXT NOT NULL DEFAULT '',
  request_digest TEXT NOT NULL,
  risk TEXT NOT NULL,
  status TEXT NOT NULL,
  exit_code INTEGER NOT NULL DEFAULT 0,
  stdout_redacted TEXT NOT NULL DEFAULT '',
  stderr_redacted TEXT NOT NULL DEFAULT '',
  stdout_cipher TEXT NOT NULL DEFAULT '',
  stderr_cipher TEXT NOT NULL DEFAULT '',
  truncated INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  ai_review_json TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_runs_host_started ON runs(host_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_digest ON runs(request_digest);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL UNIQUE,
  host_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  request_cipher TEXT NOT NULL DEFAULT '',
  request_digest TEXT NOT NULL,
  risk TEXT NOT NULL,
  status TEXT NOT NULL,
  challenge TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(id),
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at DESC);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL DEFAULT '',
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
	  tool_name TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id, created_at);
CREATE TABLE IF NOT EXISTS agent_plans (
  session_id TEXT PRIMARY KEY,
  goal TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_plan_steps (
  session_id TEXT NOT NULL,
  step_number INTEGER NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  PRIMARY KEY(session_id,step_number),
  FOREIGN KEY(session_id) REFERENCES agent_plans(session_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_agent_plan_steps_session ON agent_plan_steps(session_id,step_number);
CREATE TABLE IF NOT EXISTS session_approval_grants (
  session_id TEXT NOT NULL,
  request_fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY(session_id, request_fingerprint)
);
	CREATE TABLE IF NOT EXISTS admin_credentials (
	  id INTEGER PRIMARY KEY CHECK(id=1),
	  password_hash TEXT NOT NULL,
	  updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS web_sessions (
	  token_hash TEXT PRIMARY KEY,
	  csrf_token TEXT NOT NULL,
	  created_at TEXT NOT NULL,
	  expires_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
CREATE TABLE IF NOT EXISTS file_operations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  path TEXT NOT NULL,
  backup_path TEXT NOT NULL DEFAULT '',
  before_sha256 TEXT NOT NULL DEFAULT '',
  after_sha256 TEXT NOT NULL DEFAULT '',
  validator TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(id),
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_file_operations_host_created ON file_operations(host_id,created_at DESC);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL DEFAULT '',
  host_id TEXT NOT NULL,
  status TEXT NOT NULL,
  result_json TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  ended_at TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE INDEX IF NOT EXISTS idx_tasks_started ON tasks(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_session_approval_grants_expiry ON session_approval_grants(expires_at);
CREATE TABLE IF NOT EXISTS checkpoints (
  id TEXT PRIMARY KEY,
  data BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_providers (
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_model_providers_active ON model_providers(active) WHERE active=1;
CREATE TABLE IF NOT EXISTS system_settings (
  id INTEGER PRIMARY KEY CHECK(id=1),
  agent_max_iterations INTEGER NOT NULL,
  subagent_reviews_enabled INTEGER NOT NULL DEFAULT 1,
  beginner_explanations_enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO system_settings(id,agent_max_iterations,updated_at) VALUES(1,?,?)`,
		domain.DefaultAgentMaxIterations, formatTime(time.Now().UTC())); err != nil {
		return err
	}
	for _, statement := range []string{
		`ALTER TABLE runs ADD COLUMN request_cipher TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE approvals ADD COLUMN request_cipher TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'agent'`,
		`ALTER TABLE hosts ADD COLUMN password_cipher TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN sudo_mode TEXT NOT NULL DEFAULT 'none'`,
		`ALTER TABLE hosts ADD COLUMN sudo_password_cipher TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE chat_messages ADD COLUMN tool_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE runs ADD COLUMN ai_review_json TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE system_settings ADD COLUMN subagent_reviews_enabled INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE system_settings ADD COLUMN beginner_explanations_enabled INTEGER NOT NULL DEFAULT 1`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET auth_type='key' WHERE auth_type='agent' AND identity_file<>''`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE hosts SET auth_type='ssh_config' WHERE auth_type='agent' AND config_alias<>''`); err != nil {
		return err
	}
	return nil
}

func (s *Store) UpsertHost(ctx context.Context, host domain.Host) (domain.Host, error) {
	now := time.Now().UTC()
	if host.ID == "" {
		host.ID = ids.New("host")
		host.CreatedAt = now
	}
	if host.Port == 0 {
		host.Port = 22
	}
	host.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
INSERT INTO hosts(id,name,address,port,username,auth_type,config_alias,identity_file,known_hosts_file,proxy_jump,password_cipher,sudo_mode,sudo_password_cipher,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,address=excluded.address,port=excluded.port,
username=excluded.username,auth_type=excluded.auth_type,config_alias=excluded.config_alias,identity_file=excluded.identity_file,
known_hosts_file=excluded.known_hosts_file,proxy_jump=excluded.proxy_jump,password_cipher=excluded.password_cipher,
sudo_mode=excluded.sudo_mode,sudo_password_cipher=excluded.sudo_password_cipher,updated_at=excluded.updated_at`,
		host.ID, host.Name, host.Address, host.Port, host.User, host.AuthType, host.ConfigAlias, host.IdentityFile,
		host.KnownHostsFile, host.ProxyJump, host.PasswordCipher, host.SudoMode, host.SudoCipher,
		formatTime(host.CreatedAt), formatTime(host.UpdatedAt))
	if err != nil {
		return domain.Host{}, err
	}
	return s.GetHost(ctx, host.ID)
}

func (s *Store) GetHost(ctx context.Context, id string) (domain.Host, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,address,port,username,auth_type,config_alias,identity_file,
known_hosts_file,proxy_jump,password_cipher,sudo_mode,sudo_password_cipher,created_at,updated_at FROM hosts WHERE id=? OR name=?`, id, id)
	return scanHost(row)
}

func (s *Store) UpsertModelProvider(ctx context.Context, provider domain.ModelProvider) (domain.ModelProvider, error) {
	now := time.Now().UTC()
	if provider.ID == "" {
		provider.ID = ids.New("model")
		provider.CreatedAt = now
	}
	provider.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
INSERT INTO model_providers(id,name,kind,base_url,model,api_key_cipher,active,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,base_url=excluded.base_url,
model=excluded.model,api_key_cipher=excluded.api_key_cipher,updated_at=excluded.updated_at`,
		provider.ID, provider.Name, provider.Kind, provider.BaseURL, provider.Model, provider.APIKeyCipher,
		boolInt(provider.Active), formatTime(provider.CreatedAt), formatTime(provider.UpdatedAt))
	if err != nil {
		return domain.ModelProvider{}, err
	}
	return s.GetModelProvider(ctx, provider.ID)
}

func (s *Store) GetModelProvider(ctx context.Context, id string) (domain.ModelProvider, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,kind,base_url,model,api_key_cipher,active,created_at,updated_at
FROM model_providers WHERE id=?`, id)
	return scanModelProvider(row)
}

func (s *Store) ActiveModelProvider(ctx context.Context) (domain.ModelProvider, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,kind,base_url,model,api_key_cipher,active,created_at,updated_at
FROM model_providers WHERE active=1 LIMIT 1`)
	return scanModelProvider(row)
}

func (s *Store) ListModelProviders(ctx context.Context) ([]domain.ModelProvider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,kind,base_url,model,api_key_cipher,active,created_at,updated_at
FROM model_providers ORDER BY active DESC,name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.ModelProvider, 0)
	for rows.Next() {
		provider, err := scanModelProvider(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, provider)
	}
	return result, rows.Err()
}

func (s *Store) ActivateModelProvider(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE model_providers SET active=0 WHERE active=1`); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE model_providers SET active=1,updated_at=? WHERE id=?`, formatTime(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) DeleteModelProvider(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM model_providers WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetSystemSettings(ctx context.Context) (domain.SystemSettings, error) {
	var settings domain.SystemSettings
	var reviewsEnabled, explanationsEnabled int
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT agent_max_iterations,subagent_reviews_enabled,beginner_explanations_enabled,updated_at FROM system_settings WHERE id=1`).Scan(
		&settings.AgentMaxIterations, &reviewsEnabled, &explanationsEnabled, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SystemSettings{AgentMaxIterations: domain.DefaultAgentMaxIterations, SubagentReviewsEnabled: true, BeginnerExplanationsEnabled: true}, nil
	}
	if err != nil {
		return domain.SystemSettings{}, err
	}
	settings.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	settings.SubagentReviewsEnabled = reviewsEnabled != 0
	settings.BeginnerExplanationsEnabled = explanationsEnabled != 0
	return settings, nil
}

func (s *Store) SaveSystemSettings(ctx context.Context, settings domain.SystemSettings) (domain.SystemSettings, error) {
	settings.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `INSERT INTO system_settings(id,agent_max_iterations,subagent_reviews_enabled,beginner_explanations_enabled,updated_at) VALUES(1,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET agent_max_iterations=excluded.agent_max_iterations,subagent_reviews_enabled=excluded.subagent_reviews_enabled,
beginner_explanations_enabled=excluded.beginner_explanations_enabled,updated_at=excluded.updated_at`,
		settings.AgentMaxIterations, boolInt(settings.SubagentReviewsEnabled), boolInt(settings.BeginnerExplanationsEnabled), formatTime(settings.UpdatedAt))
	if err != nil {
		return domain.SystemSettings{}, err
	}
	return settings, nil
}

func scanModelProvider(row scanner) (domain.ModelProvider, error) {
	var provider domain.ModelProvider
	var active int
	var created, updated string
	err := row.Scan(&provider.ID, &provider.Name, &provider.Kind, &provider.BaseURL, &provider.Model,
		&provider.APIKeyCipher, &active, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ModelProvider{}, ErrNotFound
	}
	if err != nil {
		return domain.ModelProvider{}, err
	}
	provider.HasAPIKey = provider.APIKeyCipher != ""
	provider.Active = active != 0
	provider.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	provider.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return provider, nil
}

func (s *Store) ListHosts(ctx context.Context) ([]domain.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,address,port,username,auth_type,config_alias,identity_file,
known_hosts_file,proxy_jump,password_cipher,sudo_mode,sudo_password_cipher,created_at,updated_at FROM hosts WHERE auth_type<>'workspace' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Host, 0)
	for rows.Next() {
		host, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, host)
	}
	return result, rows.Err()
}

func (s *Store) DeleteHost(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

type scanner interface{ Scan(...any) error }

func scanHost(row scanner) (domain.Host, error) {
	var host domain.Host
	var created, updated string
	err := row.Scan(&host.ID, &host.Name, &host.Address, &host.Port, &host.User, &host.AuthType, &host.ConfigAlias,
		&host.IdentityFile, &host.KnownHostsFile, &host.ProxyJump, &host.PasswordCipher, &host.SudoMode,
		&host.SudoCipher, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Host{}, ErrNotFound
	}
	host.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	host.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	host.HasPassword = host.PasswordCipher != ""
	host.HasSudoPassword = host.SudoCipher != ""
	return host, err
}

func (s *Store) CreateRun(ctx context.Context, run domain.Run) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO runs(id,session_id,host_id,request_json,request_cipher,request_digest,risk,status,ai_review_json,
started_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, run.ID, run.SessionID, run.HostID, run.RequestJSON, run.RequestCipher, run.RequestDigest,
		run.Risk, run.Status, run.AIReviewJSON, formatTime(run.StartedAt))
	return err
}

func (s *Store) UpdateRun(ctx context.Context, run domain.Run) error {
	var completed any
	if !run.CompletedAt.IsZero() {
		completed = formatTime(run.CompletedAt)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status=?,exit_code=?,stdout_redacted=?,stderr_redacted=?,
stdout_cipher=?,stderr_cipher=?,truncated=?,error=?,completed_at=? WHERE id=?`, run.Status, run.ExitCode,
		run.StdoutRedacted, run.StderrRedacted, run.StdoutCipher, run.StderrCipher, boolInt(run.Truncated),
		run.Error, completed, run.ID)
	return err
}

func (s *Store) GetRun(ctx context.Context, id string) (domain.Run, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,session_id,host_id,request_json,request_cipher,request_digest,risk,status,
exit_code,stdout_redacted,stderr_redacted,stdout_cipher,stderr_cipher,truncated,error,ai_review_json,started_at,completed_at
FROM runs WHERE id=?`, id)
	return scanRun(row)
}

func (s *Store) SearchRuns(ctx context.Context, query, hostID string, limit int) ([]domain.Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	pattern := "%" + strings.ReplaceAll(query, "%", "\\%") + "%"
	rows, err := s.db.QueryContext(ctx, `SELECT id,session_id,host_id,request_json,request_cipher,request_digest,risk,status,
exit_code,stdout_redacted,stderr_redacted,stdout_cipher,stderr_cipher,truncated,error,ai_review_json,started_at,completed_at
FROM runs WHERE (?='' OR host_id=?) AND (?='' OR request_json LIKE ? ESCAPE '\' OR stdout_redacted LIKE ? ESCAPE '\'
OR stderr_redacted LIKE ? ESCAPE '\') ORDER BY started_at DESC LIMIT ?`, hostID, hostID, query, pattern, pattern, pattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, run)
	}
	return result, rows.Err()
}

func scanRun(row scanner) (domain.Run, error) {
	var run domain.Run
	var started string
	var completed sql.NullString
	var truncated int
	err := row.Scan(&run.ID, &run.SessionID, &run.HostID, &run.RequestJSON, &run.RequestCipher, &run.RequestDigest, &run.Risk,
		&run.Status, &run.ExitCode, &run.StdoutRedacted, &run.StderrRedacted, &run.StdoutCipher,
		&run.StderrCipher, &truncated, &run.Error, &run.AIReviewJSON, &started, &completed)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Run{}, ErrNotFound
	}
	if err != nil {
		return domain.Run{}, err
	}
	run.Truncated = truncated != 0
	if run.AIReviewJSON != "" {
		var review domain.CommandReview
		if json.Unmarshal([]byte(run.AIReviewJSON), &review) == nil {
			run.AIReview = &review
		}
	}
	run.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	if completed.Valid {
		run.CompletedAt, _ = time.Parse(time.RFC3339Nano, completed.String)
	}
	return run, nil
}

func (s *Store) CreateApproval(ctx context.Context, approval domain.Approval) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO approvals(id,run_id,host_id,request_json,request_cipher,request_digest,risk,
status,challenge,reason,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, approval.ID, approval.RunID,
		approval.HostID, approval.RequestJSON, approval.RequestCipher, approval.RequestDigest, approval.Risk, approval.Status,
		approval.Challenge, approval.Reason, formatTime(approval.CreatedAt), formatTime(approval.ExpiresAt))
	return err
}

func (s *Store) GetApproval(ctx context.Context, id string) (domain.Approval, error) {
	row := s.db.QueryRowContext(ctx, `SELECT approvals.id,approvals.run_id,runs.session_id,approvals.host_id,approvals.request_json,
approvals.request_cipher,approvals.request_digest,approvals.risk,approvals.status,approvals.challenge,approvals.reason,
approvals.created_at,approvals.expires_at,approvals.decided_at FROM approvals
JOIN runs ON runs.id=approvals.run_id WHERE approvals.id=?`, id)
	return scanApproval(row)
}

func (s *Store) ListApprovals(ctx context.Context, status string, limit int) ([]domain.Approval, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	now := formatTime(time.Now().UTC())
	_, _ = s.db.ExecContext(ctx, `UPDATE runs SET status='expired',error='approval expired',completed_at=?
WHERE id IN (SELECT run_id FROM approvals WHERE status='pending' AND expires_at < ?)`, now, now)
	_, _ = s.db.ExecContext(ctx, `UPDATE approvals SET status='expired',reason='approval expired',decided_at=?
WHERE status='pending' AND expires_at < ?`, now, now)
	rows, err := s.db.QueryContext(ctx, `SELECT approvals.id,approvals.run_id,runs.session_id,approvals.host_id,
approvals.request_json,approvals.request_cipher,approvals.request_digest,approvals.risk,approvals.status,
approvals.challenge,approvals.reason,approvals.created_at,approvals.expires_at,approvals.decided_at FROM approvals
JOIN runs ON runs.id=approvals.run_id WHERE (?='' OR approvals.status=?)
ORDER BY approvals.created_at DESC LIMIT ?`, status, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Approval, 0)
	for rows.Next() {
		approval, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, approval)
	}
	return result, rows.Err()
}

func (s *Store) DecideApproval(ctx context.Context, id, status, reason string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE approvals SET status=?,reason=?,decided_at=? WHERE id=? AND status='pending'`,
		status, reason, formatTime(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return fmt.Errorf("approval is missing or no longer pending")
	}
	return nil
}

func (s *Store) ApprovePending(ctx context.Context, id, reason string, expectedRisk domain.RiskLevel, expectedChallenge string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE approvals SET status='approved',reason=?,decided_at=?
WHERE id=? AND status='pending' AND risk=? AND challenge=?`, reason, formatTime(time.Now().UTC()), id, expectedRisk, expectedChallenge)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return fmt.Errorf("approval changed or is no longer pending; refresh and review the latest risk")
	}
	return nil
}

func (s *Store) UpdatePendingApprovalReview(ctx context.Context, approvalID, runID string, risk domain.RiskLevel, challenge, reviewJSON string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE approvals SET risk=?,challenge=? WHERE id=? AND run_id=? AND status='pending'`,
		risk, challenge, approvalID, runID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return fmt.Errorf("approval is no longer pending")
	}
	result, err = tx.ExecContext(ctx, `UPDATE runs SET risk=?,ai_review_json=? WHERE id=? AND status='approval_required'`,
		risk, reviewJSON, runID)
	if err != nil {
		return err
	}
	count, _ = result.RowsAffected()
	if count == 0 {
		return fmt.Errorf("approval run is no longer awaiting a decision")
	}
	return tx.Commit()
}

func (s *Store) DecideApprovalWithSessionGrant(ctx context.Context, id, reason, sessionID, fingerprint string, expiresAt time.Time, expectedRisk domain.RiskLevel, expectedChallenge string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE approvals SET status='approved',reason=?,decided_at=?
WHERE id=? AND status='pending' AND risk=? AND challenge=?`, reason, formatTime(time.Now().UTC()), id, expectedRisk, expectedChallenge)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return fmt.Errorf("approval changed or is no longer pending; refresh and review the latest risk")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO session_approval_grants(session_id,request_fingerprint,created_at,expires_at)
VALUES(?,?,?,?) ON CONFLICT(session_id,request_fingerprint) DO UPDATE SET expires_at=excluded.expires_at`,
		sessionID, fingerprint, formatTime(time.Now().UTC()), formatTime(expiresAt))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) HasSessionApprovalGrant(ctx context.Context, sessionID, fingerprint string) (bool, error) {
	now := formatTime(time.Now().UTC())
	_, _ = s.db.ExecContext(ctx, `DELETE FROM session_approval_grants WHERE expires_at<=?`, now)
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM session_approval_grants
WHERE session_id=? AND request_fingerprint=? AND expires_at>? LIMIT 1`, sessionID, fingerprint, now).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func scanApproval(row scanner) (domain.Approval, error) {
	var approval domain.Approval
	var created, expires string
	var decided sql.NullString
	err := row.Scan(&approval.ID, &approval.RunID, &approval.SessionID, &approval.HostID, &approval.RequestJSON, &approval.RequestCipher,
		&approval.RequestDigest, &approval.Risk, &approval.Status, &approval.Challenge, &approval.Reason,
		&created, &expires, &decided)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, ErrNotFound
	}
	if err != nil {
		return domain.Approval{}, err
	}
	approval.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	approval.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	if decided.Valid {
		approval.DecidedAt, _ = time.Parse(time.RFC3339Nano, decided.String)
	}
	return approval, nil
}

func (s *Store) AppendAudit(ctx context.Context, event domain.AuditEvent) error {
	data, err := json.Marshal(event.Data)
	if err != nil {
		return err
	}
	if event.ID == "" {
		event.ID = ids.New("evt")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO audit_events(id,run_id,event_type,actor,data_json,created_at)
VALUES(?,?,?,?,?,?)`, event.ID, event.RunID, event.Type, event.Actor, string(data), formatTime(event.CreatedAt))
	return err
}

func (s *Store) ListAudit(ctx context.Context, runID string, limit int) ([]domain.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,run_id,event_type,actor,data_json,created_at
FROM audit_events WHERE (?='' OR run_id=?) ORDER BY created_at DESC LIMIT ?`, runID, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		var event domain.AuditEvent
		var data, created string
		if err := rows.Scan(&event.ID, &event.RunID, &event.Type, &event.Actor, &data, &created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(data), &event.Data)
		event.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		events = append(events, event)
	}
	return events, rows.Err()
}

func (s *Store) AppendChatMessage(ctx context.Context, sessionID, role, content string, toolName ...string) error {
	name := ""
	if len(toolName) > 0 {
		name = toolName[0]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO chat_messages(id,session_id,role,content,tool_name,created_at)
VALUES(?,?,?,?,?,?)`, ids.New("msg"), sessionID, role, content, name, formatTime(time.Now().UTC()))
	return err
}

func (s *Store) ReplaceAgentPlan(ctx context.Context, plan domain.AgentPlan) (domain.AgentPlan, error) {
	now := time.Now().UTC()
	plan.CreatedAt = now
	plan.UpdatedAt = now
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AgentPlan{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_plans WHERE session_id=?`, plan.SessionID); err != nil {
		return domain.AgentPlan{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_plans(session_id,goal,status,created_at,updated_at) VALUES(?,?,?,?,?)`,
		plan.SessionID, plan.Goal, plan.Status, formatTime(plan.CreatedAt), formatTime(plan.UpdatedAt)); err != nil {
		return domain.AgentPlan{}, err
	}
	for _, step := range plan.Steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_plan_steps(session_id,step_number,title,status,evidence,updated_at) VALUES(?,?,?,?,?,?)`,
			plan.SessionID, step.Number, step.Title, step.Status, step.Evidence, formatTime(now)); err != nil {
			return domain.AgentPlan{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.AgentPlan{}, err
	}
	return s.GetAgentPlan(ctx, plan.SessionID)
}

func (s *Store) GetAgentPlan(ctx context.Context, sessionID string) (domain.AgentPlan, error) {
	var plan domain.AgentPlan
	var created, updated string
	err := s.db.QueryRowContext(ctx, `SELECT session_id,goal,status,created_at,updated_at FROM agent_plans WHERE session_id=?`, sessionID).Scan(
		&plan.SessionID, &plan.Goal, &plan.Status, &created, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AgentPlan{}, ErrNotFound
	}
	if err != nil {
		return domain.AgentPlan{}, err
	}
	plan.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	plan.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	rows, err := s.db.QueryContext(ctx, `SELECT step_number,title,status,evidence,updated_at FROM agent_plan_steps WHERE session_id=? ORDER BY step_number`, sessionID)
	if err != nil {
		return domain.AgentPlan{}, err
	}
	defer rows.Close()
	plan.Steps = make([]domain.AgentPlanStep, 0)
	for rows.Next() {
		var step domain.AgentPlanStep
		var stepUpdated string
		if err := rows.Scan(&step.Number, &step.Title, &step.Status, &step.Evidence, &stepUpdated); err != nil {
			return domain.AgentPlan{}, err
		}
		step.UpdatedAt, _ = time.Parse(time.RFC3339Nano, stepUpdated)
		plan.Steps = append(plan.Steps, step)
	}
	return plan, rows.Err()
}

func (s *Store) AdvanceAgentPlan(ctx context.Context, sessionID string, stepNumber int, status, evidence string) (domain.AgentPlan, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.AgentPlan{}, err
	}
	defer tx.Rollback()
	var currentStatus string
	err = tx.QueryRowContext(ctx, `SELECT status FROM agent_plan_steps WHERE session_id=? AND step_number=?`, sessionID, stepNumber).Scan(&currentStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AgentPlan{}, ErrNotFound
	}
	if err != nil {
		return domain.AgentPlan{}, err
	}
	if currentStatus != "in_progress" {
		return domain.AgentPlan{}, fmt.Errorf("invalid plan transition: step %d is %s, not in_progress", stepNumber, currentStatus)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_plan_steps SET status=?,evidence=?,updated_at=? WHERE session_id=? AND step_number=?`,
		status, evidence, formatTime(now), sessionID, stepNumber); err != nil {
		return domain.AgentPlan{}, err
	}
	planStatus := "blocked"
	if status == "completed" {
		var next int
		err := tx.QueryRowContext(ctx, `SELECT step_number FROM agent_plan_steps WHERE session_id=? AND step_number>? ORDER BY step_number LIMIT 1`, sessionID, stepNumber).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			planStatus = "completed"
		} else if err != nil {
			return domain.AgentPlan{}, err
		} else {
			planStatus = "active"
			if _, err := tx.ExecContext(ctx, `UPDATE agent_plan_steps SET status='in_progress',updated_at=? WHERE session_id=? AND step_number=? AND status='pending'`,
				formatTime(now), sessionID, next); err != nil {
				return domain.AgentPlan{}, err
			}
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE agent_plans SET status=?,updated_at=? WHERE session_id=?`, planStatus, formatTime(now), sessionID)
	if err != nil {
		return domain.AgentPlan{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return domain.AgentPlan{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return domain.AgentPlan{}, err
	}
	return s.GetAgentPlan(ctx, sessionID)
}

func (s *Store) ListChatMessages(ctx context.Context, sessionID string, limit int) ([]domain.ChatMessage, error) {
	return s.listChatMessages(ctx, sessionID, limit, false)
}

func (s *Store) ListChatModelMessages(ctx context.Context, sessionID string, limit int) ([]domain.ChatMessage, error) {
	return s.listChatMessages(ctx, sessionID, limit, true)
}

func (s *Store) listChatMessages(ctx context.Context, sessionID string, limit int, modelOnly bool) ([]domain.ChatMessage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	filter := ""
	if modelOnly {
		filter = " AND role IN ('user','assistant')"
	}
	query := `SELECT role,content,tool_name,created_at FROM (
SELECT role,content,tool_name,created_at FROM chat_messages WHERE session_id=?` + filter + ` ORDER BY created_at DESC LIMIT ?)
ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, query, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.ChatMessage, 0)
	for rows.Next() {
		var message domain.ChatMessage
		var created string
		if err := rows.Scan(&message.Role, &message.Content, &message.ToolName, &created); err != nil {
			return nil, err
		}
		message.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		result = append(result, message)
	}
	return result, rows.Err()
}

func (s *Store) ListChatSessions(ctx context.Context, limit int) ([]domain.ChatSession, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT messages.session_id,
  COALESCE((SELECT substr(first.content,1,80) FROM chat_messages AS first
    WHERE first.session_id=messages.session_id AND first.role='user'
    ORDER BY first.created_at ASC LIMIT 1),'New conversation') AS title,
  count(*),max(messages.created_at)
FROM chat_messages AS messages
GROUP BY messages.session_id
ORDER BY max(messages.created_at) DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.ChatSession, 0)
	for rows.Next() {
		var session domain.ChatSession
		var updated string
		if err := rows.Scan(&session.ID, &session.Title, &session.MessageCount, &updated); err != nil {
			return nil, err
		}
		session.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		result = append(result, session)
	}
	return result, rows.Err()
}

func (s *Store) DeleteChatSession(ctx context.Context, sessionID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM chat_messages WHERE session_id=?`, sessionID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM checkpoints WHERE id=?`, sessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_approval_grants WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM agent_plans WHERE session_id=?`, sessionID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Get(ctx context.Context, id string) ([]byte, bool, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT data FROM checkpoints WHERE id=?`, id).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (s *Store) Set(ctx context.Context, id string, data []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO checkpoints(id,data,updated_at) VALUES(?,?,?)
ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at`, id, data, formatTime(time.Now().UTC()))
	return err
}

func (s *Store) Delete(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM checkpoints WHERE id=?`, id)
	return err
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
