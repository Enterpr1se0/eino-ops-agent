package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddress  string        `yaml:"listen_address"`
	DataDir        string        `yaml:"data_dir"`
	DatabasePath   string        `yaml:"database_path"`
	ArtifactsDir   string        `yaml:"artifacts_dir"`
	Logging        Logging       `yaml:"logging"`
	MasterKey      string        `yaml:"-"`
	PolicyPath     string        `yaml:"policy_path"`
	OpenSSH        OpenSSH       `yaml:"openssh"`
	Model          Model         `yaml:"model"`
	Limits         Limits        `yaml:"limits"`
	AuditRetention time.Duration `yaml:"-"`
}

type Logging struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	File        string `yaml:"file"`
	AddSource   bool   `yaml:"add_source"`
	MaxSizeMB   int    `yaml:"max_size_mb"`
	MaxBackups  int    `yaml:"max_backups"`
	RecentLimit int    `yaml:"recent_limit"`
}

type OpenSSH struct {
	SSHPath           string `yaml:"ssh_path"`
	SSHKeyscanPath    string `yaml:"ssh_keyscan_path"`
	SSHKeygenPath     string `yaml:"ssh_keygen_path"`
	SFTPPath          string `yaml:"sftp_path"`
	DefaultKnownHosts string `yaml:"default_known_hosts"`
}

type Model struct {
	APIKey  string `yaml:"-"`
	BaseURL string `yaml:"base_url"`
	Name    string `yaml:"name"`
}

type Limits struct {
	SyncTimeoutSeconds int `yaml:"sync_timeout_seconds"`
	MaxTimeoutSeconds  int `yaml:"max_timeout_seconds"`
	MaxOutputBytes     int `yaml:"max_output_bytes"`
	ModelOutputBytes   int `yaml:"model_output_bytes"`
	GlobalConcurrency  int `yaml:"global_concurrency"`
	HostConcurrency    int `yaml:"host_concurrency"`
}

func Default() Config {
	return Config{
		ListenAddress: "0.0.0.0:8080",
		DataDir:       ".data",
		DatabasePath:  ".data/ops-agent.db",
		ArtifactsDir:  ".data/artifacts",
		PolicyPath:    "configs/policy.yaml",
		Logging: Logging{
			Level: "info", Format: "text", File: ".data/ops-agent.log",
			MaxSizeMB: 20, MaxBackups: 3, RecentLimit: 2000,
		},
		OpenSSH: OpenSSH{
			SSHPath:           "ssh",
			SSHKeyscanPath:    "ssh-keyscan",
			SSHKeygenPath:     "ssh-keygen",
			SFTPPath:          "sftp",
			DefaultKnownHosts: ".data/known_hosts",
		},
		Model: Model{Name: "gpt-4o-mini"},
		Limits: Limits{
			SyncTimeoutSeconds: 60,
			MaxTimeoutSeconds:  600,
			MaxOutputBytes:     10 << 20,
			ModelOutputBytes:   32 << 10,
			GlobalConcurrency:  8,
			HostConcurrency:    2,
		},
		AuditRetention: 30 * 24 * time.Hour,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	defaultDataDir := cfg.DataDir
	defaultDatabasePath := cfg.DatabasePath
	defaultArtifactsDir := cfg.ArtifactsDir
	defaultKnownHosts := cfg.OpenSSH.DefaultKnownHosts
	defaultLogFile := cfg.Logging.File
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}
		if len(data) > 0 {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return Config{}, err
			}
		}
	}
	applyEnv(&cfg)
	if cfg.DatabasePath == "" || (cfg.DataDir != defaultDataDir && cfg.DatabasePath == defaultDatabasePath && os.Getenv("OPS_AGENT_DATABASE") == "") {
		cfg.DatabasePath = filepath.Join(cfg.DataDir, "ops-agent.db")
	}
	if cfg.ArtifactsDir == "" || (cfg.DataDir != defaultDataDir && cfg.ArtifactsDir == defaultArtifactsDir && os.Getenv("OPS_AGENT_ARTIFACTS_DIR") == "") {
		cfg.ArtifactsDir = filepath.Join(cfg.DataDir, "artifacts")
	}
	if cfg.OpenSSH.DefaultKnownHosts == "" || (cfg.DataDir != defaultDataDir && cfg.OpenSSH.DefaultKnownHosts == defaultKnownHosts) {
		cfg.OpenSSH.DefaultKnownHosts = filepath.Join(cfg.DataDir, "known_hosts")
	}
	if cfg.Logging.File == "" || (cfg.DataDir != defaultDataDir && cfg.Logging.File == defaultLogFile && os.Getenv("OPS_AGENT_LOG_FILE") == "") {
		cfg.Logging.File = filepath.Join(cfg.DataDir, "ops-agent.log")
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	setString(&cfg.ListenAddress, "OPS_AGENT_LISTEN")
	setString(&cfg.DataDir, "OPS_AGENT_DATA_DIR")
	setString(&cfg.DatabasePath, "OPS_AGENT_DATABASE")
	setString(&cfg.ArtifactsDir, "OPS_AGENT_ARTIFACTS_DIR")
	setString(&cfg.PolicyPath, "OPS_AGENT_POLICY")
	setString(&cfg.Logging.Level, "OPS_AGENT_LOG_LEVEL")
	setString(&cfg.Logging.Format, "OPS_AGENT_LOG_FORMAT")
	setString(&cfg.Logging.File, "OPS_AGENT_LOG_FILE")
	setBool(&cfg.Logging.AddSource, "OPS_AGENT_LOG_SOURCE")
	setInt(&cfg.Logging.MaxSizeMB, "OPS_AGENT_LOG_MAX_SIZE_MB")
	setInt(&cfg.Logging.MaxBackups, "OPS_AGENT_LOG_MAX_BACKUPS")
	setInt(&cfg.Logging.RecentLimit, "OPS_AGENT_LOG_RECENT_LIMIT")
	setString(&cfg.MasterKey, "OPS_AGENT_MASTER_KEY")
	setString(&cfg.Model.APIKey, "OPENAI_API_KEY")
	setString(&cfg.Model.BaseURL, "OPENAI_BASE_URL")
	setString(&cfg.Model.Name, "OPENAI_MODEL")
	setInt(&cfg.Limits.GlobalConcurrency, "OPS_AGENT_GLOBAL_CONCURRENCY")
	setInt(&cfg.Limits.HostConcurrency, "OPS_AGENT_HOST_CONCURRENCY")
}

func setBool(dst *bool, name string) {
	if value := os.Getenv(name); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			*dst = parsed
		}
	}
}

func setString(dst *string, name string) {
	if value := os.Getenv(name); value != "" {
		*dst = value
	}
}

func setInt(dst *int, name string) {
	if value := os.Getenv(name); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			*dst = parsed
		}
	}
}
