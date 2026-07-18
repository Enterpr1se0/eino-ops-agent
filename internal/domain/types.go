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
	AgentMaxIterations          int       `json:"agent_max_iterations"`
	SubagentReviewsEnabled      bool      `json:"subagent_reviews_enabled"`
	BeginnerExplanationsEnabled bool      `json:"beginner_explanations_enabled"`
	UpdatedAt                   time.Time `json:"updated_at"`
}

type SystemSettingsInput struct {
	AgentMaxIterations          int   `json:"agent_max_iterations"`
	SubagentReviewsEnabled      *bool `json:"subagent_reviews_enabled,omitempty"`
	BeginnerExplanationsEnabled *bool `json:"beginner_explanations_enabled,omitempty"`
}

type MCPTransport string

const (
	MCPTransportStdio          MCPTransport = "stdio"
	MCPTransportStreamableHTTP MCPTransport = "streamable_http"
)

type MCPTool struct {
	Name        string `json:"name"`
	ExposedName string `json:"exposed_name"`
	Description string `json:"description,omitempty"`
}

type MCPServer struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Transport     MCPTransport `json:"transport"`
	Command       string       `json:"command,omitempty"`
	Args          []string     `json:"args,omitempty"`
	Cwd           string       `json:"cwd,omitempty"`
	URL           string       `json:"url,omitempty"`
	EnvKeys       []string     `json:"env_keys,omitempty"`
	HeaderKeys    []string     `json:"header_keys,omitempty"`
	SecretsCipher string       `json:"-"`
	Enabled       bool         `json:"enabled"`
	Status        string       `json:"status"`
	LastError     string       `json:"last_error,omitempty"`
	ConnectedAt   *time.Time   `json:"connected_at,omitempty"`
	ToolCount     int          `json:"tool_count"`
	Tools         []MCPTool    `json:"tools,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

type MCPServerInput struct {
	ID        string            `json:"id,omitempty"`
	Name      string            `json:"name"`
	Transport MCPTransport      `json:"transport"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Enabled   bool              `json:"enabled"`
}

type MCPTestResult struct {
	OK        bool      `json:"ok"`
	LatencyMS int64     `json:"latency_ms"`
	ToolCount int       `json:"tool_count"`
	Tools     []MCPTool `json:"tools"`
}

type WebSession struct {
	TokenHash string    `json:"-"`
	CSRFToken string    `json:"csrf_token"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
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
	Status    string    `json:"status"`
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
	ExecProgram         ExecMode = "program"
	ExecScript          ExecMode = "script"
	ExecWorkspaceRead   ExecMode = "workspace_read"
	ExecWorkspaceList   ExecMode = "workspace_list"
	ExecWorkspaceSearch ExecMode = "workspace_search"
	ExecWorkspacePatch  ExecMode = "workspace_patch"
	ExecWorkspaceUpload ExecMode = "workspace_upload"
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
	RemotePath      string            `json:"remote_path,omitempty" jsonschema:"absolute remote file path for transfers"`
	WorkspaceID     string            `json:"workspace_id,omitempty" jsonschema:"registered workspace identifier"`
	RelativePath    string            `json:"relative_path,omitempty" jsonschema:"path relative to the workspace root"`
	ExpectedSHA256  string            `json:"expected_sha256,omitempty" jsonschema:"workspace file version observed before mutation"`
	Validator       string            `json:"validator,omitempty" jsonschema:"allowlisted validator identifier"`
	SearchPattern   string            `json:"search_pattern,omitempty" jsonschema:"literal workspace search pattern"`
	OffsetBytes     int64             `json:"offset_bytes,omitempty" jsonschema:"bounded file read offset"`
	MaxBytes        int               `json:"max_bytes,omitempty" jsonschema:"bounded file read length"`
	LocalPath       string            `json:"-"`
}

type ToolMeta struct {
	ToolVersion string `json:"tool_version,omitempty"`
	OK          bool   `json:"ok"`
	Code        string `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
	Retryable   bool   `json:"retryable,omitempty"`
	NextAction  string `json:"next_action,omitempty"`
}

type ExecResult struct {
	ToolMeta
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
	File                *FileMetadata `json:"file,omitempty"`
}

type FileMetadata struct {
	OperationID   string `json:"operation_id,omitempty"`
	Path          string `json:"path"`
	Size          int64  `json:"size,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Owner         string `json:"owner,omitempty"`
	Group         string `json:"group,omitempty"`
	ModifiedUnix  int64  `json:"modified_unix,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	BeforeSHA256  string `json:"before_sha256,omitempty"`
	BackupPath    string `json:"backup_path,omitempty"`
	Validator     string `json:"validator,omitempty"`
	ValidationOK  bool   `json:"validation_ok,omitempty"`
	Sensitive     bool   `json:"sensitive,omitempty"`
	OffsetBytes   int64  `json:"offset_bytes,omitempty"`
	ReturnedBytes int    `json:"returned_bytes,omitempty"`
}

type FileOperation struct {
	ID           string    `json:"id"`
	RunID        string    `json:"run_id"`
	HostID       string    `json:"host_id"`
	Path         string    `json:"path"`
	BackupPath   string    `json:"backup_path"`
	BeforeSHA256 string    `json:"before_sha256"`
	AfterSHA256  string    `json:"after_sha256"`
	Validator    string    `json:"validator,omitempty"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type Decision struct {
	Risk     RiskLevel      `json:"risk"`
	Action   DecisionAction `json:"action"`
	Reason   string         `json:"reason"`
	RuleHits []string       `json:"rule_hits"`
}

type CommandReviewInput struct {
	Request       ExecRequest    `json:"request"`
	Policy        Decision       `json:"policy"`
	Host          HostCapability `json:"host"`
	PlanStep      string         `json:"plan_step,omitempty"`
	RequestDigest string         `json:"request_digest"`
	BeginnerMode  bool           `json:"beginner_mode"`
}

type CommandExplanation struct {
	Summary       string   `json:"summary"`
	Mechanism     string   `json:"mechanism"`
	Effects       []string `json:"effects"`
	Risks         []string `json:"risks"`
	BeginnerTips  []string `json:"beginner_tips"`
	RollbackGuide string   `json:"rollback_guide"`
}

type AIRiskReview struct {
	Risk             RiskLevel `json:"risk"`
	Recommendation   string    `json:"recommendation"`
	Confidence       float64   `json:"confidence"`
	Reasons          []string  `json:"reasons"`
	MissingEvidence  []string  `json:"missing_evidence"`
	RequiredControls []string  `json:"required_controls"`
}

type CommandReview struct {
	Status            string              `json:"status"`
	Model             string              `json:"model,omitempty"`
	DeterministicRisk RiskLevel           `json:"deterministic_risk"`
	EffectiveRisk     RiskLevel           `json:"effective_risk"`
	Explanation       *CommandExplanation `json:"explanation,omitempty"`
	RiskReview        *AIRiskReview       `json:"risk_review,omitempty"`
	Errors            []string            `json:"errors,omitempty"`
	ReviewedAt        time.Time           `json:"reviewed_at"`
}

type Run struct {
	ID             string         `json:"id"`
	SessionID      string         `json:"session_id,omitempty"`
	HostID         string         `json:"host_id"`
	RequestJSON    string         `json:"request_json"`
	RequestCipher  string         `json:"-"`
	RequestDigest  string         `json:"request_digest"`
	Risk           RiskLevel      `json:"risk"`
	Status         string         `json:"status"`
	ExitCode       int            `json:"exit_code"`
	StdoutRedacted string         `json:"stdout_redacted,omitempty"`
	StderrRedacted string         `json:"stderr_redacted,omitempty"`
	StdoutCipher   string         `json:"-"`
	StderrCipher   string         `json:"-"`
	Truncated      bool           `json:"truncated"`
	Error          string         `json:"error,omitempty"`
	AIReviewJSON   string         `json:"-"`
	AIReview       *CommandReview `json:"ai_review,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at,omitempty"`
}

type Approval struct {
	ID            string         `json:"id"`
	RunID         string         `json:"run_id"`
	SessionID     string         `json:"session_id,omitempty"`
	HostID        string         `json:"host_id"`
	RequestJSON   string         `json:"request_json"`
	RequestCipher string         `json:"-"`
	RequestDigest string         `json:"request_digest"`
	Risk          RiskLevel      `json:"risk"`
	Status        string         `json:"status"`
	Challenge     string         `json:"challenge,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	AIReview      *CommandReview `json:"ai_review,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ExpiresAt     time.Time      `json:"expires_at"`
	DecidedAt     time.Time      `json:"decided_at,omitempty"`
}

type Task struct {
	ToolMeta
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
