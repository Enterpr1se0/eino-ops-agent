package domain

import "time"

type RiskLevel string

const (
	RiskReadOnly  RiskLevel = "read_only"
	RiskChange    RiskLevel = "change"
	RiskCritical  RiskLevel = "critical"
	RiskForbidden RiskLevel = "forbidden"
)

type DecisionAction string

const (
	ActionAllow      DecisionAction = "allow"
	ActionApprove    DecisionAction = "approval_required"
	ActionBreakGlass DecisionAction = "break_glass_required"
	ActionDeny       DecisionAction = "denied"
)

type Host struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Address         string    `json:"address"`
	Port            int       `json:"port"`
	User            string    `json:"user"`
	AuthType        string    `json:"auth_type"`
	ConfigAlias     string    `json:"config_alias,omitempty"`
	IdentityFile    string    `json:"identity_file,omitempty"`
	KnownHostsFile  string    `json:"known_hosts_file,omitempty"`
	ProxyJump       string    `json:"proxy_jump,omitempty"`
	PasswordCipher  string    `json:"-"`
	HasPassword     bool      `json:"has_password"`
	SudoMode        string    `json:"sudo_mode"`
	SudoCipher      string    `json:"-"`
	HasSudoPassword bool      `json:"has_sudo_password"`
	Password        string    `json:"-"`
	SudoPassword    string    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type HostInput struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	Port           int    `json:"port"`
	User           string `json:"user"`
	AuthType       string `json:"auth_type"`
	ConfigAlias    string `json:"config_alias,omitempty"`
	IdentityFile   string `json:"identity_file,omitempty"`
	KnownHostsFile string `json:"known_hosts_file,omitempty"`
	ProxyJump      string `json:"proxy_jump,omitempty"`
	Password       string `json:"password,omitempty"`
	SudoMode       string `json:"sudo_mode"`
	SudoPassword   string `json:"sudo_password,omitempty"`
}

type HostCapability struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	AuthType string `json:"auth_type"`
	SudoMode string `json:"sudo_mode"`
}

type ModelProvider struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Kind         string    `json:"kind"`
	BaseURL      string    `json:"base_url,omitempty"`
	Model        string    `json:"model"`
	APIKeyCipher string    `json:"-"`
	HasAPIKey    bool      `json:"has_api_key"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ModelProviderInput struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	BaseURL string `json:"base_url,omitempty"`
	Model   string `json:"model"`
	APIKey  string `json:"api_key,omitempty"`
}

type ModelDiscoveryInput struct {
	ID      string  `json:"id,omitempty"`
	Kind    string  `json:"kind,omitempty"`
	BaseURL *string `json:"base_url,omitempty"`
	APIKey  string  `json:"api_key,omitempty"`
}

type ModelTestInput struct {
	ID      string  `json:"id,omitempty"`
	Kind    string  `json:"kind,omitempty"`
	BaseURL *string `json:"base_url,omitempty"`
	Model   string  `json:"model"`
	APIKey  string  `json:"api_key,omitempty"`
}

type ModelCatalog struct {
	Models []string `json:"models"`
	Count  int      `json:"count"`
}

const DefaultAgentMaxIterations = 20

type SystemSettings struct {
	AgentMaxIterations int       `json:"agent_max_iterations"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type SystemSettingsInput struct {
	AgentMaxIterations int `json:"agent_max_iterations"`
}

type ChatSession struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	MessageCount int       `json:"message_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type ChatMessage struct {
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	ToolName  string    `json:"tool_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AgentPlan struct {
	SessionID string          `json:"session_id"`
	Goal      string          `json:"goal"`
	Status    string          `json:"status"`
	Steps     []AgentPlanStep `json:"steps"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type AgentPlanStep struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	Status    string    `json:"status"`
	Evidence  string    `json:"evidence,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ExecMode string

const (
	ExecProgram  ExecMode = "program"
	ExecScript   ExecMode = "script"
	ExecUpload   ExecMode = "upload"
	ExecDownload ExecMode = "download"
)

type ExecRequest struct {
	HostID          string            `json:"host_id" jsonschema:"registered host identifier; never an address or credential"`
	Mode            ExecMode          `json:"mode,omitempty" jsonschema:"program for argv execution or script for a reviewed bash script"`
	Program         string            `json:"program,omitempty" jsonschema:"remote executable name for program mode"`
	Args            []string          `json:"args,omitempty" jsonschema:"separate arguments; do not include shell quoting"`
	Script          string            `json:"script,omitempty" jsonschema:"bash script content for script mode"`
	Cwd             string            `json:"cwd,omitempty" jsonschema:"absolute remote working directory"`
	Env             map[string]string `json:"env,omitempty" jsonschema:"non-secret environment values"`
	Elevated        bool              `json:"elevated,omitempty" jsonschema:"request root through the host sudo policy; never pass sudo or a password as a program or argument"`
	TimeoutSeconds  int               `json:"timeout_seconds,omitempty" jsonschema:"1-600 seconds for synchronous execution"`
	Reason          string            `json:"reason" jsonschema:"why this command is necessary"`
	ExpectedChanges string            `json:"expected_changes,omitempty" jsonschema:"expected server changes"`
	Rollback        string            `json:"rollback,omitempty" jsonschema:"rollback instructions for mutations"`
	ArtifactName    string            `json:"artifact_name,omitempty" jsonschema:"safe local artifact name managed by OpsPilot"`
	RemotePath      string            `json:"remote_path,omitempty" jsonschema:"absolute remote file path for transfers"`
}

type Artifact struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

type ExecResult struct {
	RunID               string        `json:"run_id"`
	Status              string        `json:"status"`
	Risk                RiskLevel     `json:"risk"`
	ApprovalID          string        `json:"approval_id,omitempty"`
	Challenge           string        `json:"challenge,omitempty"`
	OperatorInstruction string        `json:"operator_instruction,omitempty"`
	ExitCode            int           `json:"exit_code,omitempty"`
	Stdout              string        `json:"stdout,omitempty"`
	Stderr              string        `json:"stderr,omitempty"`
	Truncated           bool          `json:"truncated,omitempty"`
	Duration            time.Duration `json:"duration,omitempty"`
	PolicyHits          []string      `json:"policy_hits,omitempty"`
	CompletedAt         time.Time     `json:"completed_at,omitempty"`
}

type Decision struct {
	Risk     RiskLevel      `json:"risk"`
	Action   DecisionAction `json:"action"`
	Reason   string         `json:"reason"`
	RuleHits []string       `json:"rule_hits"`
}

type Run struct {
	ID             string    `json:"id"`
	SessionID      string    `json:"session_id,omitempty"`
	HostID         string    `json:"host_id"`
	RequestJSON    string    `json:"request_json"`
	RequestCipher  string    `json:"-"`
	RequestDigest  string    `json:"request_digest"`
	Risk           RiskLevel `json:"risk"`
	Status         string    `json:"status"`
	ExitCode       int       `json:"exit_code"`
	StdoutRedacted string    `json:"stdout_redacted,omitempty"`
	StderrRedacted string    `json:"stderr_redacted,omitempty"`
	StdoutCipher   string    `json:"-"`
	StderrCipher   string    `json:"-"`
	Truncated      bool      `json:"truncated"`
	Error          string    `json:"error,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
}

type Approval struct {
	ID            string    `json:"id"`
	RunID         string    `json:"run_id"`
	SessionID     string    `json:"session_id,omitempty"`
	HostID        string    `json:"host_id"`
	RequestJSON   string    `json:"request_json"`
	RequestCipher string    `json:"-"`
	RequestDigest string    `json:"request_digest"`
	Risk          RiskLevel `json:"risk"`
	Status        string    `json:"status"`
	Challenge     string    `json:"challenge,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	DecidedAt     time.Time `json:"decided_at,omitempty"`
}

type Task struct {
	ID        string    `json:"id"`
	RunID     string    `json:"run_id"`
	HostID    string    `json:"host_id"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
}

type AuditEvent struct {
	ID        string         `json:"id"`
	RunID     string         `json:"run_id,omitempty"`
	Type      string         `json:"type"`
	Actor     string         `json:"actor"`
	Data      map[string]any `json:"data"`
	CreatedAt time.Time      `json:"created_at"`
}
